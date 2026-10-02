package auth

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExampleSettingsAreValidJSON(t *testing.T) {
	raw, err := os.ReadFile("../../examples/claude-settings.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		APIKeyHelper string            `json:"apiKeyHelper"`
		Env          map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(settings.APIKeyHelper, "token --auto-login") || settings.Env["GOOGLE_CLAUDE_DOMAINS"] == "" {
		t.Fatalf("unexpected example settings: %+v", settings)
	}
}
