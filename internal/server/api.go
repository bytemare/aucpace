// Package server implements the server-side protocol of AuCPace
package server

import (
	"errors"

	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/pake/message"
	"github.com/bytemare/voprf"
)

// SetUserRecord is used by the server to load the input record matching the client to authenticate
func (s *Server) SetUserRecord(record interface{}) error {
	var ok bool

	s.pvr, ok = record.(*verifier.UserRecord)
	if !ok {
		return errors.New("invalid type for user record")
	}

	// The user record contains the associated OPRF private key
	sks, err := s.Crypto.NewScalar().Decode(s.pvr.SaltDerivationQ())
	if err != nil {
		return err
	}

	oid, err := voprf.FromHashToGroup(s.Crypto.Parameters.Group)
	if err != nil {
		return err
	}
	s.OPRF, err = oid.Server(sks.Bytes())

	return nil
}

// Register is the API to use during the message exchange for client registration
func (s *Server) Register(m []byte) ([]byte, error) {
	return s.registration(m)
}

// Authenticate is the API to use during the message exchange for authenticated key exchange
func (s *Server) Authenticate(m []byte) ([]byte, error) {
	return s.keyExchange(m)
}

// SessionKey returns the session key if the authenticated key exchange was successful
func (s *Server) SessionKey() []byte {
	return s.sessionKey
}

// EncodedParameters returns the 4-byte encoding of the ciphersuite parameters
func (s *Server) EncodedParameters() cryptotools.CiphersuiteEncoding {
	return s.Crypto.Parameters.Encode()
}

func (s *Server) verify(m []byte) (interface{}, error) {
	if s.Expect == message.StageTerminated {
		return nil, errors.New("the procedure should have been terminated")
	}

	if m == nil {
		return nil, errors.New("server can't handle nil message")
	}

	if s.pvr == nil {
		return nil, errors.New("no pvr set")
	}

	// Validate and decode the payload
	// return pake.DecodeMessage(s.Mode(), s.Expect, m, s.Encoding())
	return s.Expect.Decode(m, s.Encoding())
}

func (s *Server) registration(m []byte) ([]byte, error) {
	payload, err := s.verify(m)
	if err != nil {
		return nil, err
	}

	switch s.Expect {
	case message.RegisterStart:
		return s.startRegistration(payload.(*message.OPRFInit))

	case message.RegisterFinish:
		s.finishRegistration(payload.(*message.Registration))
		return nil, nil
	default:
		panic("invalid stage expectation")
	}
}

func (s *Server) keyExchange(m []byte) ([]byte, error) {
	payload, err := s.verify(m)
	if err != nil {
		return nil, err
	}

	switch s.Expect {
	case message.StageStart:
		return s.response(payload.(*message.Start))

	case message.StageAuth:
		return s.finish(payload.(*message.ExplicitAuth))

	default:
		panic("invalid stage expectation")
	}
}
