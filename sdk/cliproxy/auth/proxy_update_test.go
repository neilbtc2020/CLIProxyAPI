package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type proxyUpdateTestStore struct {
	fail  bool
	saved []*Auth
}

func (s *proxyUpdateTestStore) Save(_ context.Context, auth *Auth) (string, error) {
	if s.fail {
		return "", errors.New("sensitive-storage-error")
	}
	s.saved = append(s.saved, auth.Clone())
	return auth.FileName, nil
}
func (*proxyUpdateTestStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (*proxyUpdateTestStore) Delete(context.Context, string) error  { return nil }

func proxyManagerFixture(t *testing.T) (*Manager, *proxyUpdateTestStore, *Auth, string) {
	t.Helper()
	store := &proxyUpdateTestStore{}
	manager := NewManager(store, nil, nil)
	path := filepath.Join(t.TempDir(), "account.json")
	raw := []byte(`{"type":"codex","access_token":"token","proxy_url":"http://old.example:80"}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := manager.Register(t.Context(), &Auth{ID: "account.json", Provider: "codex", FileName: "account.json", ProxyURL: "http://old.example:80", Attributes: map[string]string{"path": path}, Metadata: map[string]any{"type": "codex", "access_token": "token", "proxy_url": "http://old.example:80"}})
	if err != nil {
		t.Fatal(err)
	}
	return manager, store, auth, ProxyUpdateRevision(auth, raw)
}
func TestProxyUpdatePersistenceFailureDoesNotPublish(t *testing.T) {
	manager, store, auth, revision := proxyManagerFixture(t)
	store.fail = true
	_, err := manager.UpdateProxyURL(t.Context(), auth.ID, revision, "http://new.example:80")
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("persistence failure missing or leaked")
	}
	current, _ := manager.GetByID(auth.ID)
	if current.ProxyURL != auth.ProxyURL || current.Generation != auth.Generation {
		t.Fatal("failed persistence published runtime change")
	}
}
func TestProxyUpdateOlderPendingPersistenceCannotUndoNewProxy(t *testing.T) {
	manager, store, old, revision := proxyManagerFixture(t)
	if _, err := manager.UpdateProxyURL(t.Context(), old.ID, revision, "http://new.example:80"); err != nil {
		t.Fatal(err)
	}
	count := len(store.saved)
	if err := manager.persist(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if len(store.saved) != count || store.saved[count-1].ProxyURL != "http://new.example:80" {
		t.Fatal("stale persistence undid proxy change")
	}
}

func TestProxyUpdateNotifiesOnlyTheChangedAccount(t *testing.T) {
	manager, _, auth, revision := proxyManagerFixture(t)
	changes, stop := manager.WatchAuthChanges(auth.ID)
	defer stop()
	other, stopOther := manager.WatchAuthChanges("another-account")
	defer stopOther()
	if _, err := manager.UpdateProxyURL(t.Context(), auth.ID, revision, "http://new.example:80"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	default:
		t.Fatal("proxy change did not wake credential observers")
	}
	select {
	case <-other:
		t.Fatal("proxy change notified a different account")
	default:
	}
}

func TestProxyUpdateAllowsInterveningRequestAccounting(t *testing.T) {
	manager, _, auth, revision := proxyManagerFixture(t)
	manager.MarkResult(t.Context(), Result{AuthID: auth.ID, Provider: "codex", Model: "gpt-6.1-sol", Success: true})
	updated, err := manager.UpdateProxyURL(t.Context(), auth.ID, revision, "http://new.example:80")
	if err != nil {
		t.Fatalf("request accounting invalidated an unchanged credential: %v", err)
	}
	if updated.Success != 1 || updated.ProxyURL != "http://new.example:80" {
		t.Fatal("proxy update lost concurrent accounting or failed to change the proxy")
	}
}
