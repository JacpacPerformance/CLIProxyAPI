package cliproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type failingCodexRuntimeStore struct {
	err error
}

func (s *failingCodexRuntimeStore) List(context.Context) ([]*coreauth.Auth, error) {
	return nil, s.err
}

func (*failingCodexRuntimeStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "", nil
}

func (*failingCodexRuntimeStore) Delete(context.Context, string) error {
	return nil
}

func newTestCodexHandler(manager *coreauth.Manager) *handlers.BaseAPIHandler {
	cfg := &config.Config{}
	return handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
}

func newFileBackedTestCodexRuntime(t *testing.T, authID, fixture string) (*CodexRuntime, string) {
	t.Helper()
	authDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(authDir, authID), []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewCodexRuntime(context.Background(), authDir)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, authID
}

func TestCodexRuntimeRejectsUnknownAuthWithoutProviderAccess(t *testing.T) {
	runtime, err := NewCodexRuntime(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Models("unknown-auth"); err == nil {
		t.Fatal("Models() accepted an unknown AuthID")
	}
	if _, err := runtime.Execute(context.Background(), "unknown-auth", "gpt-5.6-luna", []byte(`{"model":"gpt-5.6-luna"}`)); err == nil {
		t.Fatal("Execute() accepted an unknown AuthID")
	}
}

func TestCodexRuntimeAuthFailureCategoriesAreFixedAndSecretFree(t *testing.T) {
	const secretSentinel = "sentinel-secret-must-not-leak"
	if got := CodexAuthFailureCategoryOf(errors.New(secretSentinel)); got != "" {
		t.Fatalf("unclassified error category = %q, want empty", got)
	}
	tests := []struct {
		name     string
		category CodexAuthFailureCategory
		build    func(t *testing.T) (*CodexRuntime, string)
	}{
		{
			name:     "store refresh failed",
			category: CodexAuthStoreRefreshFailed,
			build: func(t *testing.T) (*CodexRuntime, string) {
				manager := coreauth.NewManager(&failingCodexRuntimeStore{err: errors.New(secretSentinel)}, nil, nil)
				return &CodexRuntime{manager: manager, handler: newTestCodexHandler(manager)}, "fake@example.test"
			},
		},
		{
			name:     "auth not found",
			category: CodexAuthNotFound,
			build: func(t *testing.T) (*CodexRuntime, string) {
				runtime, err := NewCodexRuntime(context.Background(), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return runtime, "missing@example.test.json"
			},
		},
		{
			name:     "auth disabled",
			category: CodexAuthDisabled,
			build: func(t *testing.T) (*CodexRuntime, string) {
				return newFileBackedTestCodexRuntime(t, "disabled@example.test.json", `{"type":"codex","disabled":true}`)
			},
		},
		{
			name:     "provider mismatch",
			category: CodexAuthProviderMismatch,
			build: func(t *testing.T) (*CodexRuntime, string) {
				return newFileBackedTestCodexRuntime(t, "provider@example.test.json", `{"type":"claude"}`)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, authID := test.build(t)
			_, err := runtime.Models(authID)
			if err == nil {
				t.Fatal("Models() error = nil")
			}
			if got := CodexAuthFailureCategoryOf(err); got != test.category {
				t.Fatalf("category = %q, want %q", got, test.category)
			}
			if strings.Contains(err.Error(), secretSentinel) || strings.Contains(err.Error(), authID) {
				t.Fatalf("error leaked sensitive input: %q", err)
			}
		})
	}
}

func TestCodexRuntimeModelsLoadsFakeAtAuthIDAndPlanCatalog(t *testing.T) {
	authDir := t.TempDir()
	authID := "codex-user@example.test-plus.json"
	runtime, err := NewCodexRuntime(context.Background(), authDir)
	if err != nil {
		t.Fatal(err)
	}
	defer GlobalModelRegistry().UnregisterClient(authID)
	fixture := []byte(`{"type":"codex","email":"user@example.test","plan_type":"plus","access_token":"fake-token"}`)
	if err := os.WriteFile(filepath.Join(authDir, authID), fixture, 0o600); err != nil {
		t.Fatal(err)
	}

	models, err := runtime.Models(authID)
	if err != nil {
		t.Fatalf("Models() error = %v", err)
	}
	if len(models) == 0 {
		t.Fatal("Models() returned no supported text models")
	}
	for _, model := range models {
		if model == nil || model.ID == "" {
			t.Fatalf("invalid model projection: %#v", model)
		}
	}
	if _, err := runtime.Models("codex-other@example.test-plus.json"); err == nil {
		t.Fatal("Models() accepted a different AuthID")
	}
}
