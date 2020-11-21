// Package client implements the client-side protocol of AuCPace
package client

import (
	"fmt"

	"github.com/bytemare/pake/message"
)

func (c *Client) registerFinish(p *message.OPRFResponse) ([]byte, error) {
	// Unblind OPRF input
	salt, err := c.oprfFinish(p.RespBlind)
	if err != nil {
		return nil, err
	}

	// Build the verifier
	verifier, err := c.verifier(p.Extra, salt)
	if err != nil {
		return nil, err
	}

	c.Expect = message.StageTerminated

	reg := message.Registration{Verifier: verifier}

	return reg.Encode(c.Encoding())
}

func (c *Client) verifier(s, salt []byte) ([]byte, error) {
	w, err := c.pwHash(s, salt)
	if err != nil {
		return nil, err
	}

	//scalar, err := group.NewScalar(nil).Decode(w)
	//if err != nil {
	//	// Something went wrong, XW might be neutral element, MUST abort
	//	return nil, errors.Wrap(err, "abort")
	//}
	//res := group.NewElement(nil).Base().Mult()

	sc, err := c.Crypto.NewScalar().Decode(w)
	if err != nil {
		return nil, fmt.Errorf("failed to build verifier : %w", err)
	}

	return c.Crypto.Base().Mult(sc).Bytes(), nil
}

func (c *Client) pwHash(s, salt []byte) ([]byte, error) {
	// Rebuild the hash function and its parameters
	hf, err := c.Crypto.Parameters.IHF.Decode(s, c.Encoding())
	if err != nil {
		return nil, fmt.Errorf("decoding password key derivation parameters : %w", err)
	}

	return hf.HashVar(salt, c.username, c.password, s), nil
}
