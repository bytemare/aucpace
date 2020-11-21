// Package internal groups the inner mechanism and unexported API for the AuCPace protocol
package internal

import (
	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/cpace"
	"github.com/bytemare/pake"
)

const dsi5 = "AuCPace25519"

// DsiSessionKey returns the DSI used for the AuCPace secret key hashing input
func DsiSessionKey() []byte {
	return []byte(dsi5)
}

// AuCPace is the AuCPace core common to both initiator and responder instances
type AuCPace struct {
	// Pake engine
	*pake.Core

	// Protocol related information
	PvrType verifier.PVRType

	// session relation information
	Ssid []byte
	Ad   []byte

	// Authentication Tags
	Tag, PeerTagVerifier []byte

	// Authenticated Key Exchange Protocol
	CPace *cpace.CPace
}
