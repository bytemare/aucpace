// Package server implements the server-side protocol of AuCPace
package server

import (
	"bytes"
	"errors"

	"github.com/bytemare/aucpace/internal"
	"github.com/bytemare/cpace"
	"github.com/bytemare/pake/message"
)

func (s *Server) initCPace(username, wxs []byte) (*message.Kex, error) {
	var err error
	p := &cpace.Parameters{
		ID:       s.Sni,
		PeerID:   username,
		Secret:   wxs,
		SID:      s.Ssid,
		AD:       s.Ad,
		Encoding: s.Encoding(),
	}

	c, err := cpace.Client(p, s.Crypto.Parameters)
	if err != nil {
		return nil, err
	}

	cp, ok := c.(*cpace.CPace)
	if !ok {
		return nil, internal.ErrCPaceAssert
	}

	s.CPace = cp

	return s.CPace.AuthenticateKex(nil)
}

func (s *Server) response(p *message.Start) ([]byte, error) {
	// Verify the user record for the user was loaded
	if s.pvr == nil {
		panic("password verifier record wasn't loaded")
	}

	if !bytes.Equal(p.UserID, s.pvr.Username) {
		return nil, errors.New("username in message doesn't match the username in pvr")
	}

	// build the oprf response
	response, sharedSecret, err := s.oprfResponse(&p.OPRFInit)
	if err != nil {
		return nil, err
	}

	// initiate CPace key exchange protocol
	y, err := s.initCPace(p.UserID, sharedSecret)
	if err != nil {
		return nil, err
	}

	// final message
	m := &message.Response{
		OPRFResponse: *response,
		Kex:          *y,
	}

	s.Expect = message.StageAuth

	return m.Encode(s.Encoding())
}

func (s *Server) authTags() {
	isk := s.CPace.SessionKey()

	s.Tag = internal.DsiInitiatorTag(s.Crypto.Hash, isk)
	s.PeerTagVerifier = internal.DsiResponderTag(s.Crypto.Hash, isk)
}

// finish performs client tag verification and returns the own tag to be sent to the client
func (s *Server) finish(p *message.ExplicitAuth) ([]byte, error) {
	// finish CPace sub-steps
	_, err := s.CPace.AuthenticateKex(p)
	if err != nil {
		return nil, err
	}

	// build and verify authentication tags
	s.authTags()

	if err := internal.VerifyPeerTag(s.PeerTagVerifier, p.Auth); err != nil {
		return nil, err
	}

	// build the AuCPace session key
	s.sessionKey = s.Crypto.HKDF(s.CPace.SessionKey(), s.Ssid, internal.DsiSessionKey(), 0)

	s.Expect = message.StageTerminated

	kex := message.Kex{
		Element: nil,
		Auth:    s.Tag,
	}

	return kex.Encode(s.Encoding())
}
