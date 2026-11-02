#!/usr/bin/env python3
"""Build verified main revisions on the server and publish the isolated 8238 instance.

Run as root from a clean main checkout. Runtime secrets stay in private release
artifacts. The existing compose service, network, credentials and mounts are kept.
Failures after promotion restore the prior image/config/plugin and running state.
"""
import argparse
import copy
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

import yaml

TARGET = Path('/home/ubuntu/deployments/cpa-8238')
CONTAINER = 'cli-proxy-api-8238'
PLUGIN = 'cpa-account-config-manager'
PORT = 8238


def command(args, *, log=None, cwd=None):
    result = subprocess.run([str(x) for x in args], cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    if log:
        Path(log).write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {args[0]}; log={log}')
    return result.stdout.decode()


def git(repo, *args):
    owner = pwd.getpwuid(repo.stat().st_uid).pw_name
    return command(['runuser', '-u', owner, '--', 'git', '-C', repo, *args]).strip()


def fetch_main(repo, expected):
    if git(repo, 'status', '--porcelain'):
        raise RuntimeError(f'checkout is not clean: {repo}')
    git(repo, 'fetch', 'origin', 'main')
    actual = git(repo, 'rev-parse', 'refs/remotes/origin/main')
    if actual != expected:
        raise RuntimeError(f'main changed: expected {expected}, found {actual}')
    if git(repo, 'branch', '--show-current') != 'main':
        raise RuntimeError(f'checkout must be on main: {repo}')
    git(repo, 'merge', '--ff-only', 'origin/main')
    if git(repo, 'rev-parse', 'HEAD') != expected:
        raise RuntimeError('checkout does not match the verified main revision')


def inspect(name):
    return json.loads(command(['docker', 'inspect', name]))[0]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def request(base, path, token=None, body=None, timeout=15):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None
    if body is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as response:
            return response.status, dict(response.headers), json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        return error.code, dict(error.headers), payload


def wait_ready(base):
    for _ in range(45):
        try:
            status, _, body = request(base, '/healthz', timeout=2)
            if status == 200 and body.get('status') == 'ok':
                return
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise RuntimeError('health check did not become ready')


def verify_service(base, admin, api_key, sha, plugin_version):
    wait_ready(base)
    status, headers, runtime_config = request(base, '/v0/management/config', admin)
    commit = {key.lower(): value for key, value in headers.items()}.get('x-cpa-commit')
    if status != 200 or commit != sha:
        raise RuntimeError('management endpoint does not report the published SHA')
    status, _, plugins = request(base, '/v0/management/plugins', admin)
    manager = next((p for p in plugins.get('plugins', []) if p.get('id') == PLUGIN), {})
    if status != 200 or not manager.get('registered') or not manager.get('effective_enabled'):
        raise RuntimeError('account manager plugin is not active')
    if (manager.get('metadata') or {}).get('version') != plugin_version:
        raise RuntimeError('account manager version does not match the built artifact')
    status, _, _ = request(base, '/v0/management/plugins/' + PLUGIN + '/accounts', admin)
    if status != 200:
        raise RuntimeError('account manager accounts flow failed')
    status, _, fingerprint = request(base, '/v0/management/plugins/' + PLUGIN + '/codex/fingerprint', admin)
    values = {field['key']: field.get('value') for field in fingerprint.get('profile', {}).get('fields', [])}
    if status != 200 or values.get('version') != '0.166.0':
        raise RuntimeError('plugin effective Codex version is not 0.166.0')
    status, _, models = request(base, '/v1/models', api_key)
    if status != 200 or not isinstance(models.get('data'), list):
        raise RuntimeError('authenticated model listing failed')
    unauth, _, _ = request(base, '/v1/models')
    if unauth != 401:
        raise RuntimeError('unauthenticated API access was not rejected')
    return {'health': 'ok', 'commit': commit, 'plugin_version': plugin_version,
            'codex_version': values['version'], 'models': len(models['data']),
            'model_ids': [item['id'] for item in models['data'] if isinstance(item.get('id'), str)],
            'unauthenticated_status': unauth,
            'bootstrap_buffering': runtime_config.get('codex', {}).get('stream-bootstrap-buffering'),
            'bootstrap_timeout': runtime_config.get('codex', {}).get('stream-bootstrap-timeout')}


def select_smoke_model(available, requested):
    if requested:
        if requested not in available:
            raise RuntimeError('requested smoke model is not advertised by this instance')
        return requested
    for preferred in ['gpt-6.1-sol', 'gpt-6-sol', 'gpt-5.6-sol', 'gpt-5.6-luna', 'gpt-6-luna']:
        for model in available:
            if model.rsplit('/', 1)[-1] == preferred:
                return model
    raise RuntimeError('no supported text model is available for inference verification')


def prepare_plugin_config(config, version, enable_bootstrap_buffering=False):
    config.setdefault('upstream', {}).setdefault('codex', {})['disable-codex-cloaking'] = False
    if enable_bootstrap_buffering:
        codex = config['upstream']['codex']
        codex['stream-bootstrap-buffering'] = True
        codex['stream-bootstrap-timeout'] = '5s'
    manager = config.setdefault('plugins', {}).setdefault('configs', {}).setdefault(PLUGIN, {})
    manager['enabled'] = True
    manager.setdefault('store', {})['version'] = version
    return manager


def install_plugin(root, library, version):
    folder = root / 'plugins/linux/amd64'
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob(PLUGIN + '*.so'):
        old.rename(old.with_suffix(old.suffix + '.before-codex-0166'))
    destination = folder / f'{PLUGIN}-v{version}.so'
    shutil.copy2(library, destination)
    destination.chmod(0o755)
    # These three old identity overrides would shadow the new compiled defaults.
    profile = root / 'plugins/data' / PLUGIN / 'codex-fingerprint-profile.json'
    if profile.exists():
        payload = json.loads(profile.read_text())
        values = payload.get('values', {})
        for key in ['user_agent', 'originator', 'version']:
            values.pop(key, None)
        write_json(profile, payload)
    return file_hash(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--plugin-source', required=True, type=Path)
    parser.add_argument('--plugin-sha', required=True)
    parser.add_argument('--smoke-model', help='Optional exact model ID; otherwise select an advertised text model')
    parser.add_argument('--enable-bootstrap-buffering', action='store_true',
                        help='Buffer non-output events for safe overload failover; release on the next event after 5s')
    parser.add_argument('--allow-unverified-upstream', action='store_true',
                        help='Explicit operator waiver: keep a healthy deployment when existing upstream credentials cannot pass inference')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('run this release script as root')
    if not all(re.fullmatch('[0-9a-f]{40}', sha) for sha in [args.sha, args.plugin_sha]):
        raise RuntimeError('full verified commit SHAs are required')
    os.umask(0o077)
    lock = open('/var/lock/cpa-8238-release.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    repo = Path(__file__).resolve().parents[1]
    print('Fetching and checking the verified main revisions', flush=True)
    fetch_main(repo, args.sha)
    fetch_main(args.plugin_source, args.plugin_sha)
    previous = inspect(CONTAINER)
    expected_mounts = {
        '/CLIProxyAPI/config.yaml': TARGET / 'config.yaml',
        '/root/.cli-proxy-api': TARGET / 'auths',
        '/CLIProxyAPI/plugins': TARGET / 'plugins',
    }
    mounts = {item['Destination']: Path(item['Source']) for item in previous['Mounts']}
    if any(mounts.get(destination) != source or source.is_symlink() for destination, source in expected_mounts.items()):
        raise RuntimeError('target mounts differ from the approved 8238 instance')
    if previous['HostConfig']['PortBindings'].get('8317/tcp') != [{'HostIp': '0.0.0.0', 'HostPort': str(PORT)}]:
        raise RuntimeError('target port binding differs from 8238')
    compose = yaml.safe_load((TARGET / 'compose.yaml').read_text())
    if set(compose.get('services', {})) != {CONTAINER}:
        raise RuntimeError('compose file contains services outside this release scope')
    config = yaml.safe_load((TARGET / 'config.yaml').read_text())
    environment = dict(item.split('=', 1) for item in previous['Config']['Env'])
    admin = environment.get('MANAGEMENT_PASSWORD')
    keys = config.get('access', {}).get('api-keys') or config.get('api-keys')
    if not admin or not isinstance(keys, list) or not keys or not isinstance(keys[0], str):
        raise RuntimeError('existing management and API credentials are required')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    release = TARGET / 'releases' / (stamp + '-' + args.sha[:12])
    release.mkdir(parents=True, mode=0o700)
    write_json(release / 'previous-container.private.json', previous)
    backup = release / 'backup'
    backup.mkdir()
    for name in ['config.yaml', 'compose.yaml', '.env.credentials']:
        shutil.copy2(TARGET / name, backup / name)
    for name in ['auths', 'plugins']:
        shutil.copytree(TARGET / name, backup / name)
    config_hash = file_hash(TARGET / 'config.yaml')
    compose_hash = file_hash(TARGET / 'compose.yaml')
    other_before = inspect('cli-proxy-api-8237')['Id']
    image = 'local/cpa-8238:' + args.sha
    builder = 'local/cpa-8238-builder:' + args.sha
    plugin_version = '0.3.1510-codexfp.' + args.sha[:12]
    build_args = ['--build-arg', 'VERSION=8.0.0-codexfp.' + args.sha[:12],
                  '--build-arg', 'COMMIT=' + args.sha, '--build-arg', 'BUILD_DATE=' + stamp,
                  '--label', 'org.opencontainers.image.revision=' + args.sha]
    print('Building Linux core and running fingerprint transport checks', flush=True)
    command(['docker', 'build', '--target', 'builder', '-t', builder, *build_args, '.'],
            cwd=repo, log=release / 'core-builder.log')
    command(['docker', 'run', '--rm', '--cpus', '4', '-e', 'GOMAXPROCS=4', builder,
             'go', 'test', '-race', './internal/runtime/executor/helps', './internal/runtime/executor',
             './internal/thinking', './internal/translator/codex/openai/chat-completions', './sdk/cliproxy/auth',
             '-run', 'Test.*(Codex|ToolResultsSurviveInterleaved|BootstrapOverload)',
             '-count=1'], log=release / 'core-fingerprint-tests.log')
    command(['docker', 'build', '-t', image, *build_args, '.'], cwd=repo, log=release / 'core-image.log')
    plugin_tree = release / 'plugin-source'
    plugin_tree.mkdir()
    archive = subprocess.check_output(['runuser', '-u', pwd.getpwuid(args.plugin_source.stat().st_uid).pw_name,
                                      '--', 'git', '-C', str(args.plugin_source), 'archive', args.plugin_sha,
                                      'cpa-account-config-manager'])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(plugin_tree, filter='data')
    plugin_tree /= 'cpa-account-config-manager'
    print('Building the matching account plugin from its committed main revision', flush=True)
    command(['docker', 'run', '--rm', '--cpus', '4', '-e', 'GOMAXPROCS=4', '-v', str(plugin_tree) + ':/plugin',
             '-w', '/plugin', builder, 'sh', '-ec',
             'go test -race ./internal/manager -run "TestCodex(AccountFingerprintMatchesCore|AccountManagementFingerprintMatchesInference|FingerprintMetadataStaysASCII)" -count=1 && '
             'CGO_ENABLED=1 go build -buildvcs=false -buildmode=c-shared -ldflags "-X cpa-account-config-manager/internal/manager.PluginVersion=' + plugin_version + '" -o /plugin/release.so .'],
            log=release / 'plugin-build.log')
    canary = release / 'canary'
    canary.mkdir()
    for name in ['plugins', 'static']:
        shutil.copytree(TARGET / name, canary / name)
    for name in ['auths', 'logs']:
        (canary / name).mkdir()
    canary_config = copy.deepcopy(config)
    manager = prepare_plugin_config(canary_config, plugin_version, args.enable_bootstrap_buffering)
    manager.setdefault('automation', {})['enabled'] = False
    manager.setdefault('inspection_policy', {})['enabled'] = False
    manager.setdefault('default_policy', {})['enabled'] = False
    canary_config.setdefault('server', {}).update({'host': '', 'port': 8317, 'tls': {'enable': False}})
    canary_config.setdefault('oauth', {})['auth-dir'] = '/root/.cli-proxy-api'
    management = copy.deepcopy(config.get('management') or config.get('remote-management') or {})
    management['allow-remote'] = True
    canary_config['management'] = management
    (canary / 'config.yaml').write_text(yaml.safe_dump(canary_config, sort_keys=False))
    env_file = release / 'canary-env.private'
    env_file.write_text('MANAGEMENT_PASSWORD=' + admin + '\n')
    plugin_hash = install_plugin(canary, plugin_tree / 'release.so', plugin_version)
    candidate = 'cpa-8238-check-' + args.sha[:12]
    promoted = False
    report = {'sha': args.sha, 'plugin_sha': args.plugin_sha, 'image': image,
              'plugin_version': plugin_version, 'plugin_sha256': plugin_hash, 'release_dir': str(release)}
    try:
        print('Starting an isolated candidate with no production credentials', flush=True)
        run_args = ['docker', 'run', '-d', '--name', candidate, '--label', 'cpa.release=' + args.sha,
                    '--env-file', env_file, '-p', '127.0.0.1::8317']
        for source, destination in [('config.yaml', '/CLIProxyAPI/config.yaml'), ('auths', '/root/.cli-proxy-api'),
                                    ('plugins', '/CLIProxyAPI/plugins'), ('logs', '/CLIProxyAPI/logs'), ('static', '/CLIProxyAPI/static')]:
            run_args += ['-v', str(canary / source) + ':' + destination]
        command([*run_args, image])
        candidate_port = inspect(candidate)['NetworkSettings']['Ports']['8317/tcp'][0]['HostPort']
        report['candidate'] = verify_service('http://127.0.0.1:' + candidate_port, admin, keys[0], args.sha, plugin_version)
        command(['docker', 'logs', candidate], log=release / 'candidate-container.log')
        command(['docker', 'rm', '-f', candidate])
        if file_hash(TARGET / 'config.yaml') != config_hash or file_hash(TARGET / 'compose.yaml') != compose_hash:
            raise RuntimeError('target configuration changed during the candidate build')
        print('Candidate passed; promoting only the 8238 service', flush=True)
        promoted = True
        install_plugin(TARGET, plugin_tree / 'release.so', plugin_version)
        prepare_plugin_config(config, plugin_version, args.enable_bootstrap_buffering)
        (TARGET / 'config.yaml').write_text(yaml.safe_dump(config, sort_keys=False))
        compose['services'][CONTAINER]['image'] = image
        (TARGET / 'compose.yaml').write_text(yaml.safe_dump(compose, sort_keys=False))
        command(['docker', 'compose', '-f', TARGET / 'compose.yaml', 'up', '-d', '--no-deps', '--force-recreate', '--no-build', '--pull', 'never', CONTAINER],
                cwd=TARGET, log=release / 'promotion.log')
        base = f'http://127.0.0.1:{PORT}'
        report['production'] = verify_service(base, admin, keys[0], args.sha, plugin_version)
        if args.enable_bootstrap_buffering and (not report['production']['bootstrap_buffering'] or report['production']['bootstrap_timeout'] != '5s'):
            raise RuntimeError('bootstrap failover configuration was not applied')
        live = inspect(CONTAINER)
        built = json.loads(command(['docker', 'image', 'inspect', image]))[0]
        if live['Image'] != built['Id'] or built['Config']['Labels']['org.opencontainers.image.revision'] != args.sha:
            raise RuntimeError('running image does not match the built revision')
        if live['State'].get('OOMKilled') or live['RestartCount']:
            raise RuntimeError('new container restarted or was killed')
        report['image_id'] = live['Image']
        print('Checking authenticated Responses inference and recent service logs', flush=True)
        smoke_model = select_smoke_model(report['production']['model_ids'], args.smoke_model)
        try:
            status, _, body = request(base, '/v1/responses', keys[0],
                                      {'model': smoke_model, 'input': 'Reply exactly OK.', 'reasoning': {'effort': 'low'}, 'stream': False}, timeout=90)
        except (OSError, ValueError) as error:
            if not args.allow_unverified_upstream:
                raise
            status, body = None, {'error': {'type': type(error).__name__, 'code': 'smoke_transport_failure'}}
        output_text = ' '.join(part.get('text', '') for item in body.get('output', []) if isinstance(item, dict) for part in item.get('content', []) if isinstance(part, dict))
        report['inference'] = {'model': smoke_model, 'status': status, 'response_status': body.get('status'), 'output_contains_ok': 'OK' in output_text,
                               'error_type': (body.get('error') or {}).get('type'),
                               'error_code': (body.get('error') or {}).get('code')}
        command(['docker', 'logs', CONTAINER], log=release / 'production-container.log')
        logs = (release / 'production-container.log').read_text(errors='replace')
        report['log_review'] = {'error_lines': sum('level=error' in line for line in logs.splitlines()), 'fatal_or_panic': bool(re.search(r'level=fatal|panic:', logs))}
        if report['log_review']['fatal_or_panic']:
            raise RuntimeError('fatal error in production container logs')
        inference_passed = status == 200 and body.get('status') == 'completed' and report['inference']['output_contains_ok']
        report['inference']['passed'] = inference_passed
        report['inference']['operator_waiver'] = args.allow_unverified_upstream and not inference_passed
        if not inference_passed and not args.allow_unverified_upstream:
            write_json(release / 'verification.json', report)
            raise RuntimeError(f'live inference smoke failed with HTTP {status}')
        if inspect('cli-proxy-api-8237')['Id'] != other_before:
            raise RuntimeError('8237 changed concurrently; investigate before declaring completion')
        report['unrelated_8237_unchanged'] = True
        report['result'] = 'published' if inference_passed else 'published_with_unverified_upstream'
        write_json(release / 'verification.json', report)
        print(json.dumps(report), flush=True)
    except BaseException:
        report['result'] = 'preflight_failed'
        write_json(release / 'verification.json', report)
        if promoted:
            print('Release verification failed; restoring the previous 8238 image and settings', flush=True)
            command(['docker', 'compose', '-f', TARGET / 'compose.yaml', 'stop', CONTAINER], cwd=TARGET, log=release / 'rollback-stop.log')
            for name in ['config.yaml', 'compose.yaml']:
                shutil.copy2(backup / name, TARGET / name)
            shutil.rmtree(TARGET / 'plugins')
            shutil.copytree(backup / 'plugins', TARGET / 'plugins')
            rollback_compose = yaml.safe_load((TARGET / 'compose.yaml').read_text())
            rollback_compose['services'][CONTAINER]['image'] = previous['Config']['Image']
            (TARGET / 'compose.yaml').write_text(yaml.safe_dump(rollback_compose, sort_keys=False))
            command(['docker', 'compose', '-f', TARGET / 'compose.yaml', 'up', '-d', '--no-deps', '--force-recreate', '--no-build', '--pull', 'never', CONTAINER], cwd=TARGET, log=release / 'rollback.log')
            if not previous['State']['Running']:
                command(['docker', 'compose', '-f', TARGET / 'compose.yaml', 'stop', CONTAINER], cwd=TARGET)
            report['result'] = 'rolled_back'
            write_json(release / 'verification.json', report)
        raise
    finally:
        if subprocess.run(['docker', 'inspect', candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            command(['docker', 'logs', candidate], log=release / 'candidate-container.log')
        subprocess.run(['docker', 'rm', '-f', candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
