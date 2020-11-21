// Package server implements the server-side protocol of AuCPace
package server

import (
	"errors"
	"fmt"

	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

func (s *Server) oprfResponse(p *message.OPRFInit) (*message.OPRFResponse, []byte, error) {
	sharedSecret, publicKey, err := s.start()
	if err != nil {
		return nil, nil, err
	}

	// OPRF signature
	uq, err := s.sign(p.InitBlind)
	if err != nil {
		return nil, nil, err
	}

	// Piggyback sigma parameters
	sigma, err := s.Encoding().Encode(s.pvr.IHF)
	if err != nil {
		return nil, nil, err
	}

	response := &message.OPRFResponse{
		RespBlind:     uq,
		PublicOPRFKey: publicKey,
		Extra:         sigma,
	}

	return response, sharedSecret, nil
}

func (s *Server) start() (sharedSecret, publicKey []byte, err error) {
	// Generate secret scalar and use it as the OPRF private key
	// privateKey := s.Cipher.RandomScalar()
	privateKey := s.Crypto.NewScalar().Random()

	// Generate a corresponding OPRF public key using the group's base point
	publicKey = s.Crypto.Base().Mult(privateKey).Bytes()

	//publicKey. group.NewElement(nil).Base().Mult(privateKey)
	//publicKey, err = s.Cipher.ScalarMultBase(privateKey)
	//if err != nil {
	//	return nil, nil, err
	//}

	// The shared secret will be ???
	W := s.pvr.Verifier()

	if s.Mode() == pake.KeyExchange {
		if len(W) == 0 {
			return nil, nil, errors.New("user verifier is empty or nil")
		}

		v, err := s.Crypto.NewElement().Decode(W)
		if err != nil {
			return nil, nil, fmt.Errorf("failed decoding verifier : %w", err)
		}

		sharedSecret = v.Mult(privateKey).Bytes()

		// sharedSecret, err = s.Cipher.ScalarMult(privateKey, W)
	}

	return sharedSecret, publicKey, err
}

func (s *Server) sign(u []byte) (uq []byte, err error) {
	if s.pvr.PvrType == verifier.SAPVD {
		ev, err := s.OPRF.Evaluate(u)
		if err != nil {
			return nil, err
		}

		return ev.Encode(s.Encoding())
	}

	return s.pvr.SaltDerivationQ(), nil
}
