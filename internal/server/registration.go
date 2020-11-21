// Package server implements the server-side protocol of AuCPace
package server

import (
	"github.com/bytemare/pake/message"
)

func (s *Server) startRegistration(p *message.OPRFInit) ([]byte, error) {
	// Verify a user record for the user was loaded
	if s.pvr == nil {
		panic("password verifier record wasn't loaded")
	}

	// on registration, we don't use wxs
	m, _, err := s.oprfResponse(p)
	if err != nil {
		return nil, err
	}

	s.Expect = message.RegisterFinish

	return m.Encode(s.Encoding())
}

func (s *Server) finishRegistration(p *message.Registration) {
	// todo : explore encrypting W with a pwKDF(wxs, W) on the client to protect it during setup
	s.pvr.SetVerifier(p.Verifier)
	s.Expect = message.StageTerminated
}
