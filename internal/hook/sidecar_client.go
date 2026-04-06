package hook

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/sidecar"
)

type sidecarResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// EvaluateViaSidecar connects to the sidecar Unix socket, sends the event,
// and returns the policy decision. Fail-closed: returns (false, reason, err)
// on any communication error.
func EvaluateViaSidecar(socketPath string, event *agent.HookEvent) (bool, string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false, "sidecar unreachable", fmt.Errorf("dial sidecar: %w", err)
	}
	defer conn.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return false, "encode error", fmt.Errorf("marshal event: %w", err)
	}

	if err := sidecar.WriteMessage(conn, data); err != nil {
		return false, "write error", fmt.Errorf("write to sidecar: %w", err)
	}

	respData, err := sidecar.ReadMessage(conn)
	if err != nil {
		return false, "read error", fmt.Errorf("read from sidecar: %w", err)
	}

	var resp sidecarResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return false, "decode error", fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.Allowed, resp.Reason, nil
}
