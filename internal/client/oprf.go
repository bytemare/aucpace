// Package client implements the client-side protocol of AuCPace
package client

import (
	"fmt"

	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/pake/message"
)

// oprfStart initiates the client side first step of the AuCPace protocol by returning the blinding U, to be sent to the server
func (c *Client) oprfStart() *message.OPRFInit {
	// Generate a secret internal blinder and use it to blind our input
	blinded := c.OPRF.Blind(append(c.username, c.password...))

	return &message.OPRFInit{
		UserID:    c.username,
		InitBlind: blinded,
	}
}

func (c *Client) oprfFinish(uq []byte) ([]byte, error) {
	// todo : the salt generated here must be secure and cleared from memory as soon as possible
	if c.PvrType == verifier.SAPVD {
		//if err := c.OPRF.DecodeEvaluation(uq, c.Encoding()); err != nil {
		//	return nil, err
		//}

		if _, err := c.OPRF.Unblind(uq, nil, nil); err != nil {
			return nil, err
		}

		return c.OPRF.Finalize()[0], nil
	}

	return uq, nil
}

func (c *Client) sessionPassword(s, x, salt []byte) ([]byte, error) {
	w, err := c.pwHash(s, salt)
	if err != nil {
		return nil, err
	}

	// sharedSecret, err := group.Mult(w, x)

	sharedSecret, err := c.Crypto.MultBytes(w, x)
	if err != nil {
		// Something went wrong, XW might be neutral element, MUST abort
		return nil, fmt.Errorf("abort : %w", err)
	}

	return sharedSecret.Bytes(), nil
}
