// Package client implements the client-side protocol of AuCPace
package client

import (
	"github.com/bytemare/aucpace/internal"
	"github.com/bytemare/voprf"
)

// Client implements the Pake interface
type Client struct {
	// User information
	username, password []byte

	// session secret
	sessionKey []byte // todo : this is sensitive info

	// AuCPace engine
	OPRF *voprf.Client
	*internal.AuCPace
}

// New returns a pointer to an initialised Client structure
func New(username, password []byte, oprf *voprf.Client, aucpace *internal.AuCPace) *Client {
	return &Client{
		username: username,
		password: password,
		OPRF:     oprf,
		AuCPace:  aucpace,
	}
}
