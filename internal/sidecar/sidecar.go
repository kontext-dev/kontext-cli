// Package sidecar implements the local session server.
// It runs as a persistent process alongside the agent, listening on a Unix socket.
// Hook handlers communicate with the sidecar instead of spawning HTTP requests —
// this eliminates per-hook latency entirely.
package sidecar

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Server is the local sidecar that hook handlers communicate with.
type Server struct {
	socketPath string
	listener   net.Listener
	mu         sync.Mutex
	// TODO: policy cache, credential cache, backend streaming connection
}

// New creates a new sidecar server with a Unix socket in the given directory.
func New(sessionDir string) (*Server, error) {
	socketPath := filepath.Join(sessionDir, "kontext.sock")
	return &Server{socketPath: socketPath}, nil
}

// SocketPath returns the Unix socket path for hook handlers to connect to.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start begins listening on the Unix socket.
func (s *Server) Start(ctx context.Context) error {
	// Clean up stale socket
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("sidecar: listen: %w", err)
	}
	s.listener = ln

	go s.serve(ctx)
	return nil
}

// Stop shuts down the sidecar and cleans up the socket.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
}

func (s *Server) serve(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(_ context.Context, conn net.Conn) {
	defer conn.Close()
	// TODO: read hook event from conn, evaluate, write decision back
	// Protocol: length-prefixed JSON over Unix socket
}
