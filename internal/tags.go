package internal

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/hash"
)

const (
	dsi3 = "AuCPace25-Ta"
	dsi4 = "AuCPace25-Tb"
)

// DsiInitiatorTag returns the tag associated to the initiator
func DsiInitiatorTag(h *hash.Hash, isk []byte) []byte {
	return h.Hmac([]byte(dsi3), isk)
}

// DsiResponderTag returns the tag associated to the responder
func DsiResponderTag(h *hash.Hash, isk []byte) []byte {
	return h.Hmac([]byte(dsi4), isk)
}

// VerifyPeerTag returns whether the peer tag matches the expected verifier tag
func VerifyPeerTag(peerTagVerifier, peerTag []byte) error {
	if len(peerTag) == 0 {
		return errors.New("peer authentication Tag is empty or nil")
	}

	if hmac.Equal(peerTagVerifier, peerTag) {
		return nil // Peer tag is validated, no error
	}

	return errors.New("invalid peer tag : must abort")
}
