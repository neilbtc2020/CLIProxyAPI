package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrProxyUpdateConflict    = errors.New("account changed; reload before changing its proxy")
	ErrProxyUpdateUnavailable = errors.New("account proxy update is unavailable")
)

// ProxyUpdateRevision binds a UI selection to both its runtime incarnation and
// its exact physical document. It exposes neither credentials nor file paths.
func ProxyUpdateRevision(auth *Auth, raw []byte) string {
	if auth == nil || len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	sum := sha256.New()
	// Request accounting also increments Generation in v8. It must not make an
	// otherwise unchanged account impossible to edit while serving traffic.
	_, _ = fmt.Fprintf(sum, "proxy-update-v2\x00%s\x00%d\x00", auth.ID, auth.RegistrationEpoch)
	_, _ = sum.Write(raw)
	return hex.EncodeToString(sum.Sum(nil))
}

// UpdateProxyURL changes one field on the current credential. The persistence
// lock prevents older pending writes from undoing this change, while m.mu keeps
// refresh and replacement from changing the selected account during the CAS.
func (m *Manager) UpdateProxyURL(ctx context.Context, id, expectedRevision, proxyURL string) (*Auth, error) {
	if m == nil || len(expectedRevision) != 64 {
		return nil, ErrProxyUpdateConflict
	}
	if _, err := hex.DecodeString(expectedRevision); err != nil {
		return nil, ErrProxyUpdateConflict
	}
	releaseMutation, errMutation := m.lockAuthMutationContext(ctx, id)
	if errMutation != nil {
		return nil, errMutation
	}
	defer releaseMutation()
	lockValue, _ := m.persistLocks.LoadOrStore(id, &authPersistLock{})
	persistLock := lockValue.(*authPersistLock)
	persistLock.mu.Lock()
	m.mu.Lock()
	updated, err := m.updateProxyURLLocked(ctx, id, expectedRevision, proxyURL, persistLock)
	m.mu.Unlock()
	persistLock.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Use the v8 publication hooks after releasing all mutation/persistence locks.
	releaseMutation()
	m.finishAuthUpdate(ctx, updated, false)
	return updated.Clone(), nil
}

func (m *Manager) updateProxyURLLocked(ctx context.Context, id, expectedRevision, proxyURL string, persistLock *authPersistLock) (*Auth, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current := m.auths[id]
	if current == nil || IsConfigAPIKeyAuth(current) || IsPluginVirtualAuth(current) {
		return nil, ErrProxyUpdateUnavailable
	}
	path := strings.TrimSpace(current.Attributes["path"])
	if path == "" || !filepath.IsAbs(path) || !strings.HasSuffix(strings.ToLower(path), ".json") {
		return nil, ErrProxyUpdateUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, ErrProxyUpdateConflict
	}
	raw, err := os.ReadFile(path)
	if err != nil || ProxyUpdateRevision(current, raw) != expectedRevision {
		return nil, ErrProxyUpdateConflict
	}
	// A GetAuth call can observe a new disk document before the watcher updates
	// memory, or new runtime tokens before their pending persistence completes.
	// Reject such mixed snapshots even when their supplied revision matches.
	var diskMetadata map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&diskMetadata) != nil || diskMetadata == nil {
		return nil, ErrProxyUpdateConflict
	}
	NormalizeCredentialMetadata(diskMetadata)
	// FileTokenStore materializes disabled=false during its first persistence,
	// after the runtime clone has been published. Treat an omitted false value
	// as equivalent without accepting a changed disabled flag.
	if _, exists := diskMetadata["disabled"]; !exists {
		diskMetadata["disabled"] = false
	}
	runtimeMetadata := current.Clone().Metadata
	if runtimeMetadata == nil {
		return nil, ErrProxyUpdateUnavailable
	}
	if _, exists := runtimeMetadata["disabled"]; !exists {
		runtimeMetadata["disabled"] = current.Disabled
	}
	diskCanonical, errDisk := json.Marshal(diskMetadata)
	runtimeCanonical, errRuntime := json.Marshal(runtimeMetadata)
	if errDisk != nil || errRuntime != nil || !bytes.Equal(diskCanonical, runtimeCanonical) {
		return nil, ErrProxyUpdateConflict
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || document == nil {
		return nil, ErrProxyUpdateConflict
	}
	updated := current.Clone()
	if updated.Metadata == nil {
		return nil, ErrProxyUpdateUnavailable
	}
	updated.ProxyURL = strings.TrimSpace(proxyURL)
	updated.Metadata["proxy_url"] = updated.ProxyURL
	updated.Generation++
	updated.UpdatedAt = time.Now()
	if m.store != nil {
		if _, err = m.store.Save(ctx, updated); err != nil {
			return nil, errors.New("could not persist account proxy")
		}
	} else {
		document["proxy_url"], err = json.Marshal(updated.ProxyURL)
		if err != nil {
			return nil, ErrProxyUpdateUnavailable
		}
		data, errMarshal := json.Marshal(document)
		if errMarshal != nil {
			return nil, ErrProxyUpdateUnavailable
		}
		if err = writeProxyAuthDocument(path, data); err != nil {
			return nil, errors.New("could not persist account proxy")
		}
	}
	persistLock.lastEpoch, persistLock.lastGeneration = updated.RegistrationEpoch, updated.Generation
	m.auths[id] = updated.Clone()
	m.notifyAuthChangeLocked(id)
	return updated, nil
}

func writeProxyAuthDocument(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".proxy-update-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
