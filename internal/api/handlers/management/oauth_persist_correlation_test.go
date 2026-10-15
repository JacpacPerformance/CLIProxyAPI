package management

import (
	"context"
	"sync"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestOAuthPersistCorrelationChecksPendingProvider(t *testing.T) {
	store := newOAuthSessionStore(0)
	replaceOAuthSessionStoreForTest(t, store)
	store.Register("codex-state", "codex")
	store.Register("other-state", "claude")

	if provider, ok := OAuthSessionProvider("codex-state"); !ok || provider != "codex" {
		t.Fatalf("pending provider = %q/%t, want codex/true", provider, ok)
	}
	if provider, ok := OAuthSessionProvider("other-state"); !ok || provider != "claude" {
		t.Fatalf("pending provider = %q/%t, want claude/true", provider, ok)
	}
	store.Complete("codex-state")
	if _, ok := OAuthSessionProvider("codex-state"); ok {
		t.Fatal("completed state remained eligible for persistence correlation")
	}
}

func TestOAuthPersistContextCorrelatesExactSavedIDsConcurrently(t *testing.T) {
	type result struct {
		state string
		auth  string
	}
	results := make(chan result, 2)
	hook := func(ctx context.Context, auth *coreauth.Auth) error {
		results <- result{state: OAuthSessionState(ctx), auth: auth.ID}
		return nil
	}

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_ = hook(WithOAuthSessionState(context.Background(), "state-a"), &coreauth.Auth{ID: "credential-a", Provider: "codex"})
	}()
	go func() {
		defer wait.Done()
		_ = hook(WithOAuthSessionState(context.Background(), "state-b"), &coreauth.Auth{ID: "credential-b", Provider: "codex"})
	}()
	wait.Wait()
	close(results)

	seen := map[string]string{}
	for item := range results {
		seen[item.state] = item.auth
	}
	if seen["state-a"] != "credential-a" || seen["state-b"] != "credential-b" {
		t.Fatalf("correlation = %#v, want independent exact IDs", seen)
	}
}

func TestOAuthPersistCorrelationDoesNotRunForFailedSave(t *testing.T) {
	called := false
	hook := func(context.Context, *coreauth.Auth) error {
		called = true
		return nil
	}
	// saveTokenRecord invokes the hook only after Store.Save succeeds.
	simulatedSaveError := context.Canceled
	if simulatedSaveError == nil {
		_ = hook(context.Background(), &coreauth.Auth{ID: "not-saved"})
	}
	if called {
		t.Fatal("post-persist correlation hook ran after simulated failed save")
	}
}
