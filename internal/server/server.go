// Package server implements the server-side protocol of AuCPace
package server

import (
	"github.com/bytemare/aucpace/internal"
	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/voprf"
)

// Server implements the Pake interface
type Server struct {
	// User related info
	pvr *verifier.UserRecord

	// session secret
	sessionKey []byte // todo : this is sensitive info

	// AuCPace engine
	OPRF *voprf.Server
	*internal.AuCPace
}

// New returns a pointer to an initialised Server struct
func New(aucpace *internal.AuCPace) *Server {
	return &Server{
		AuCPace: aucpace,
	}
}
