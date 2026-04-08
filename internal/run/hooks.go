package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type claudeSettings struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Hooks []hookDef `json:"hooks"`
}

type hookDef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// GenerateSettings creates a Claude Code settings.json with Kontext hooks
// and returns the path to the generated file.
func GenerateSettings(sessionDir, kontextBinary, agentName string) (string, error) {
	hookCmd := fmt.Sprintf("%s hook --agent %s", kontextBinary, agentName)

	settings := claudeSettings{
		Hooks: map[string][]hookGroup{
			"PreToolUse": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
			"PostToolUse": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
			"UserPromptSubmit": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
		},
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal settings: %w", err)
	}

	settingsPath := filepath.Join(sessionDir, "settings.json")
	if err := os.WriteFile(settingsPath, data, 0600); err != nil {
		return "", fmt.Errorf("write settings: %w", err)
	}

	return settingsPath, nil
}
