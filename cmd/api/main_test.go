package main

import (
	"testing"

	"github.com/micanis/paperlens/backend/internal/config"
	"github.com/micanis/paperlens/backend/internal/provider"
)

func TestSelectProviderUsesSafeDevelopmentProvider(t *testing.T) {
	if got := selectProvider(config.Config{AppEnv: "development"}); got.Name() != (provider.EchoProvider{}).Name() {
		t.Fatalf("provider = %q, want development echo", got.Name())
	}
}

func TestSelectProviderFailsClosedWhenManagedKeyIsConfiguredButAdapterIsNot(t *testing.T) {
	got := selectProvider(config.Config{AppEnv: "production", ManagedLLMAPIKey: "configured", ManagedLLMModel: "model"})
	if got.Name() != "paperlens-managed" {
		t.Fatalf("provider = %q, want paperlens-managed", got.Name())
	}
}
