package sidecar

import (
	"net"

	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

type EvaluateRequest = localruntime.EvaluateRequest
type EvaluateResult = localruntime.EvaluateResult

func WriteMessage(conn net.Conn, v any) error {
	return localruntime.WriteMessage(conn, v)
}

func ReadMessage(conn net.Conn, v any) error {
	return localruntime.ReadMessage(conn, v)
}
