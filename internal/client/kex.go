// Package client implements the client-side protocol of AuCPace
package client

import (
	"github.com/bytemare/aucpace/internal"
	"github.com/bytemare/cpace"
	"github.com/bytemare/pake/message"
)

func (c *Client) initCPace(sharedSecret []byte) error {
	p := &cpace.Parameters{
		ID:       c.username,
		PeerID:   c.Sni,
		Secret:   sharedSecret,
		SID:      c.Ssid,
		AD:       c.Ad,
		Encoding: c.Encoding(),
	}

	cl, err := cpace.Server(p, c.Crypto.Parameters)
	if err != nil {
		return err
	}

	cp, ok := cl.(*cpace.CPace)
	if !ok {
		return internal.ErrCPaceAssert
	}

	c.CPace = cp

	return err
}

func (c *Client) response(p *message.Response) ([]byte, error) {
	// Sub step 1 : Unblind OPRF input
	salt, err := c.oprfFinish(p.RespBlind)
	if err != nil {
		return nil, err
	}

	// Sub step 2 : calculate XWs
	sharedSecret, err := c.sessionPassword(p.Extra, p.PublicOPRFKey, salt)
	if err != nil {
		return nil, err
	}

	// sub step 3 : CPace response
	if err := c.initCPace(sharedSecret); err != nil {
		return nil, err
	}

	kex, err := c.CPace.AuthenticateKex(&p.Kex)
	if err != nil {
		return nil, err
	}

	// sub step 4 : build authentication steps
	c.authTags()

	kex.Auth = c.Tag

	c.Expect = message.StageAuth

	return kex.Encode(c.Encoding())
}

func (c *Client) authTags() {
	isk := c.CPace.SessionKey()

	c.Tag = internal.DsiResponderTag(c.Crypto.Hash, isk)
	c.PeerTagVerifier = internal.DsiInitiatorTag(c.Crypto.Hash, isk)
}

func (c *Client) finish(p *message.ExplicitAuth) error {
	// Verify authentication tag
	if err := internal.VerifyPeerTag(c.PeerTagVerifier, p.Auth); err != nil {
		return err
	}

	// Build AuCPace session key
	c.sessionKey = c.Crypto.HKDF(c.CPace.SessionKey(), c.Ssid, internal.DsiSessionKey(), 0)

	c.Expect = message.StageTerminated

	return nil
}
