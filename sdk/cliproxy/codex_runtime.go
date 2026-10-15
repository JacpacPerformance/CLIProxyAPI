package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// CodexRuntime is the embeddable, per-AuthID Codex execution surface.
// It owns one SDK auth manager and never selects a credential from the request.
type CodexRuntime struct {
	manager *coreauth.Manager
	handler *handlers.BaseAPIHandler
}

// CodexStreamChunk is one downstream streaming payload or terminal error.
type CodexStreamChunk struct {
	Payload []byte
	Err     error
}

// CodexAuthFailureCategory is a fixed, non-secret diagnostic classification.
type CodexAuthFailureCategory string

const (
	CodexAuthStoreRefreshFailed CodexAuthFailureCategory = "store_refresh_failed"
	CodexAuthNotFound           CodexAuthFailureCategory = "auth_not_found"
	CodexAuthDisabled           CodexAuthFailureCategory = "auth_disabled"
	CodexAuthProviderMismatch   CodexAuthFailureCategory = "provider_mismatch"
)

type codexAuthFailure struct {
	category CodexAuthFailureCategory
}

func (e *codexAuthFailure) Error() string {
	return "cliproxy: Codex credential is unavailable"
}

// CodexAuthFailureCategoryOf returns only the fixed diagnostic category.
func CodexAuthFailureCategoryOf(err error) CodexAuthFailureCategory {
	var failure *codexAuthFailure
	if errors.As(err, &failure) {
		return failure.category
	}
	return ""
}

// NewCodexRuntime loads native CLIProxy credentials from authDir and prepares
// the real SDK Codex executor. The directory is read only by the SDK store.
func NewCodexRuntime(ctx context.Context, authDir string) (*CodexRuntime, error) {
	if strings.TrimSpace(authDir) == "" {
		return nil, fmt.Errorf("cliproxy: auth directory is required")
	}
	store := auth.GetTokenStore()
	if dirSetter, ok := store.(interface{ SetBaseDir(string) }); ok {
		dirSetter.SetBaseDir(authDir)
	}
	manager := coreauth.NewManager(store, nil, nil)
	cfg := &config.Config{AuthDir: authDir}
	manager.SetConfig(cfg)
	manager.RegisterExecutor(executor.NewCodexAutoExecutor(cfg))
	if err := manager.Load(ctx); err != nil {
		return nil, fmt.Errorf("cliproxy: load Codex credentials: %w", err)
	}
	runtime := &CodexRuntime{
		manager: manager,
		handler: handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager),
	}
	for _, item := range manager.List() {
		runtime.registerModels(item)
	}
	return runtime, nil
}

func (r *CodexRuntime) registerModels(authRecord *coreauth.Auth) {
	if authRecord == nil || authRecord.Disabled || !strings.EqualFold(authRecord.Provider, "codex") {
		return
	}
	models := registry.GetCodexProModels()
	switch strings.ToLower(strings.TrimSpace(authRecord.Attributes["plan_type"])) {
	case "free":
		models = registry.GetCodexFreeModels()
	case "plus":
		models = registry.GetCodexPlusModels()
	case "team", "business", "go":
		models = registry.GetCodexTeamModels()
	}
	GlobalModelRegistry().RegisterClient(authRecord.ID, "codex", models)
}

func (r *CodexRuntime) auth(ctx context.Context, authID string) (*coreauth.Auth, error) {
	if r == nil || r.manager == nil || r.handler == nil {
		return nil, fmt.Errorf("cliproxy: Codex runtime is unavailable")
	}
	for _, item := range r.manager.List() {
		if item != nil && strings.EqualFold(item.Provider, "codex") {
			GlobalModelRegistry().UnregisterClient(item.ID)
		}
	}
	if err := r.manager.Load(ctx); err != nil {
		return nil, &codexAuthFailure{category: CodexAuthStoreRefreshFailed}
	}
	for _, item := range r.manager.List() {
		r.registerModels(item)
	}
	authRecord, ok := r.manager.GetByID(authID)
	if !ok || authRecord == nil {
		return nil, &codexAuthFailure{category: CodexAuthNotFound}
	}
	if authRecord.Disabled {
		return nil, &codexAuthFailure{category: CodexAuthDisabled}
	}
	if !strings.EqualFold(authRecord.Provider, "codex") {
		return nil, &codexAuthFailure{category: CodexAuthProviderMismatch}
	}
	return authRecord, nil
}

func executionError(message *interfaces.ErrorMessage) error {
	if message == nil {
		return nil
	}
	if message.Error != nil {
		return message.Error
	}
	return fmt.Errorf("cliproxy: Codex execution failed with status %d", message.StatusCode)
}

// Execute runs one non-streaming request pinned to authID.
func (r *CodexRuntime) Execute(ctx context.Context, authID, model string, body []byte) (handlers.ModelExecutionResponse, error) {
	if _, err := r.auth(ctx, authID); err != nil {
		return handlers.ModelExecutionResponse{}, err
	}
	response, message := r.handler.ExecuteModel(ctx, handlers.ModelExecutionRequest{
		EntryProtocol:  "openai",
		ExitProtocol:   "openai",
		Model:          model,
		Body:           body,
		ForcedProvider: "codex",
		AuthID:         authID,
	})
	if err := executionError(message); err != nil {
		return handlers.ModelExecutionResponse{}, err
	}
	return response, nil
}

// ExecuteStream runs one streaming request pinned to authID.
func (r *CodexRuntime) ExecuteStream(ctx context.Context, authID, model string, body []byte) (handlers.ModelExecutionStream, <-chan CodexStreamChunk, error) {
	if _, err := r.auth(ctx, authID); err != nil {
		return handlers.ModelExecutionStream{}, nil, err
	}
	stream, message := r.handler.ExecuteModelStream(ctx, handlers.ModelExecutionRequest{
		EntryProtocol:  "openai",
		ExitProtocol:   "openai",
		Model:          model,
		Stream:         true,
		Body:           body,
		ForcedProvider: "codex",
		AuthID:         authID,
	})
	if err := executionError(message); err != nil {
		return handlers.ModelExecutionStream{}, nil, err
	}
	chunks := make(chan CodexStreamChunk)
	go func() {
		defer close(chunks)
		for chunk := range stream.Chunks {
			var err error
			if chunk.Err != nil {
				err = fmt.Errorf("cliproxy: Codex stream failed: %s", chunk.Err.Error())
			}
			chunks <- CodexStreamChunk{Payload: chunk.Payload, Err: err}
		}
	}()
	return stream, chunks, nil
}

// Models returns the current SDK catalog for the exact active AuthID.
func (r *CodexRuntime) Models(authID string) ([]*ModelInfo, error) {
	authRecord, err := r.auth(context.Background(), authID)
	if err != nil {
		return nil, err
	}
	models := GlobalModelRegistry().GetModelsForClient(authRecord.ID)
	result := make([]*ModelInfo, 0, len(models))
	for _, model := range models {
		if model == nil || !supportsText(model) {
			continue
		}
		result = append(result, model)
	}
	return result, nil
}

func supportsText(model *ModelInfo) bool {
	if model == nil {
		return false
	}
	return containsFold(model.SupportedInputModalities, "text") && containsFold(model.SupportedOutputModalities, "text")
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
