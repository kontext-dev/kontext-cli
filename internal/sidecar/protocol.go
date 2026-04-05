package sidecar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// EvaluateRequest is sent from kontext hook → sidecar over Unix socket.
type EvaluateRequest struct {
	Type         string          `json:"type"` // "evaluate"
	Agent        string          `json:"agent"`
	HookEvent    string          `json:"hook_event"`
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID    string          `json:"tool_use_id"`
	CWD          string          `json:"cwd"`
}

// EvaluateResult is sent from sidecar → kontext hook.
type EvaluateResult struct {
	Type    string `json:"type"` // "result"
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// WriteMessage writes a length-prefixed JSON message to a connection.
// Wire format: 4-byte big-endian length + JSON payload.
func WriteMessage(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ReadMessage reads a length-prefixed JSON message from a connection.
func ReadMessage(conn net.Conn, v any) error {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read length: %w", err)
	}

	if length > 10*1024*1024 { // 10MB safety limit
		return fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	return json.Unmarshal(data, v)
}
