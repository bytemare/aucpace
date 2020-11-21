// Package client implements the client-side protocol of AuCPace
package client

import (
	"errors"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

// SetUserRecord is only used by the server to load the input record matching the client to authenticate
func (c *Client) SetUserRecord(_ interface{}) error {
	return errors.New("can't call SetUserRecord in client role")
}

// Register needs to be called consecutively for the registration steps, and returns a message to send to the peer.
//
// Calling Register() with nil, indicates starting the registration process.
// Calling Register() with the server response will finish the process and return the final message to send to the server.
func (c *Client) Register(m []byte) ([]byte, error) {
	return c.handle(m)
}

// Authenticate is to be called successively throughout the whole AuCPace process with the received message.
// The response, if any, should be send to the peer.
//
// The first call should be with nil as argument, and all subsequent calls should be the server responses to previous messages.
func (c *Client) Authenticate(m []byte) ([]byte, error) {
	return c.handle(m)
}

// SessionKey returns the AuCPace shared session key, if and only if all Authenticate() steps have succeeded.
func (c *Client) SessionKey() []byte {
	return c.sessionKey
}

// EncodedParameters returns the 4-byte encoding of the ciphersuite parameters
func (c *Client) EncodedParameters() cryptotools.CiphersuiteEncoding {
	return c.Crypto.Parameters.Encode()
}

func (c *Client) startAuCPace() ([]byte, error) {
	return c.oprfStart().Encode(c.Encoding())
}

func (c *Client) handle(m []byte) ([]byte, error) {
	if c.Expect == message.StageTerminated {
		return nil, errors.New("the procedure should have been terminated")
	}

	if m == nil {
		return c.startAuCPace()
	}

	// Validate and decode the payload
	// payload, err := pake.DecodeMessage(c.Mode(), c.Expect, m, c.Encoding())
	payload, err := c.Expect.Decode(m, c.Encoding())
	if err != nil {
		return nil, err
	}

	switch c.Mode() {
	case pake.Registration:
		return c.registerFinish(payload.(*message.OPRFResponse))
	case pake.KeyExchange:
		return c.keyExchange(payload)
	}

	panic("invalid mode")
}

func (c *Client) keyExchange(payload interface{}) ([]byte, error) {
	switch c.Expect {
	case message.StageResponse:
		// This is the server's response to the OPRF, and the CPace initiation
		return c.response(payload.(*message.Response))
	case message.StageAuth:
		// This is the server's authentication tag
		return nil, c.finish(payload.(*message.ExplicitAuth))
	default:
		panic("invalid stage expectation")
	}
}
