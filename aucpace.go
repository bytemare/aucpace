// Package aucpace implements the (strong) AuCPace asymmetric password authenticated key exchange (aPAKE) protocol
package aucpace

import (
	"fmt"

	"github.com/bytemare/aucpace/internal"
	"github.com/bytemare/aucpace/internal/client"
	"github.com/bytemare/aucpace/internal/server"
	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/pake"
	"github.com/bytemare/voprf"
)

// Mode is a pake.Mode alias
type Mode pake.Mode

const (
	// Registration sets the PAKE as a password registration procedure
	Registration = Mode(pake.Initiator)

	// Authentication sets the PAKE as a client authentication procedure
	Authentication = Mode(pake.Responder)

	minSidLength = 16

	protocol = "(strong)-AuCPace"
	version  = "0.0.0"
)

// Parameters groups a party's input parameters
type Parameters struct {
	// SSID
	SSID []byte

	// AD
	AD []byte

	// SNI
	SNI []byte

	// UserID
	UserID []byte

	// Secret
	Secret []byte

	// Encoding
	Encoding encoding.Encoding
}

func newAuCPace(mode pake.Mode, role pake.Role, parameters *Parameters, csp *cryptotools.Parameters) (*internal.AuCPace, error) {
	// todo : add missing argument checks
	if parameters.SSID != nil && len(parameters.SSID) < minSidLength {
		panic(fmt.Sprintf("ssid is too short (< %d)", minSidLength))
	}

	if err := parameters.Encoding.Available(); err != nil {
		return nil, err
	}

	// meta := pake.MetaData()

	core, err := mode.New(protocol, version, parameters.Encoding, csp, role, parameters.SNI)
	if err != nil {
		return nil, err
	}

	return &internal.AuCPace{
		Core:    core,
		PvrType: verifier.SAPVD,
		Ssid:    parameters.SSID,
		Ad:      parameters.SSID,
		CPace:   nil,
	}, nil
}

// Client returns a newly instantiated AuCPace client for the given mode.
//
// The cryptographic engine is configured through the ciphersuite parameters, and can be nil to use the defaults.
// sni identifies the server (server name indication), and userID the client.
// userID is not used when creating a server, and a user record MUST be added before engaging in a response.
// secret defines either the user password or the server's private key's seed.
func (m Mode) Client(parameters *Parameters, csp *cryptotools.Parameters) (pake.AugmentedPake, error) {
	if len(parameters.UserID) == 0 {
		panic("userID cannot be empty or nil for the client")
	}

	if len(parameters.Secret) == 0 {
		panic("secret/password can not be empty or nil")
	}

	aucpace, err := newAuCPace(pake.Mode(m), pake.Initiator, parameters, csp)
	if err != nil {
		return nil, err
	}

	op, err := voprf.FromHashToGroup(aucpace.Core.Crypto.Parameters.Group)
	if err != nil {
		return nil, err
	}

	oprf, err := op.Client(nil)
	if err != nil {
		return nil, err
	}

	return client.New(parameters.UserID, parameters.Secret, oprf, aucpace), nil
}

// Client returns a newly instantiated AuCPace server for the given mode.
// To be able to handle client requests, there must be a subsequent loading of the client record.
func (m Mode) Server(parameters *Parameters, csp *cryptotools.Parameters) (pake.AugmentedPake, error) {
	aucpace, err := newAuCPace(pake.Mode(m), pake.Initiator, parameters, csp)
	if err != nil {
		return nil, err
	}

	return server.New(aucpace), nil
}

// NewUserRecord provides a quick way to create a user entry
// Todo : this is for the POC. A proper way to handle user records must be implemented
func NewUserRecord(userID []byte, csp *cryptotools.Parameters) (*verifier.UserRecord, error) {
	i := csp.IHF.Get(int(csp.IHFLen))
	return verifier.PvrInit(verifier.SAPVD, i, csp, userID)
}
