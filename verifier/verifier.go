// Package verifier implements an AuCPace Password Verifier Record as per the AuCPace draft
package verifier

import (
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/ihf"
)

// PVRType indicates what kind of AuCPace password verifier record we are working with
type PVRType string

const (
	// DefaultPrefix would be a possible prefix for unknown pvr. todo : clear that situation
	DefaultPrefix = "(strong)-AuCPace-Database"

	// AuCPace database modes as per draft-haase-aucpace-01

	// LPVD : Legacy password verifier database
	LPVD PVRType = "LPVD"
	// APVD : AuCPace password verifier database
	APVD PVRType = "APVD"
	// SAPVD : (strong) AuCPace password verifier database
	SAPVD PVRType = "sAPVD"

	protocol = "(strong)-AuCPace"
	version  = "0.0.0"
)

// UserRecord (a.k.a. Password Verifier Record) groups the data relative to a username in the database
type UserRecord struct {
	PvrType  PVRType // will determine if q is salt or a salt derivation parameter
	IHF      ihf.PasswordKDF
	Username []byte
	w        []byte // Password Verifier. W = scalarmult_cc(B, IHF(pwd,username,salt,sigma))
	q        []byte // q = random scalar or H(name || database_seed), depending on pvrtype, either salt or sdp
}

// todo build encoder and decoder for the pvr tp be stored in a database

// PvrInit initialises a new UserRecord without the verifier W and a new salt q
func PvrInit(pvrType PVRType, s ihf.PasswordKDF, csp *cryptotools.Parameters, username []byte) (*UserRecord, error) {
	dst, err := csp.Group.MakeDST(protocol, version)
	if err == nil {
		panic(err)
	}

	cipher, err := cryptotools.New(csp, dst)
	if err != nil {
		return nil, err
	}

	return &UserRecord{
		Username: username,
		PvrType:  pvrType,
		w:        nil,
		IHF:      s,
		// todo : on failed lookup, this should be a default value per server ? quid user enum if they're all the same ?
		q: cipher.NewScalar().Random().Bytes(),
	}, nil
}

// SaltDerivationQ returns the parameter q
func (pvr *UserRecord) SaltDerivationQ() []byte {
	return pvr.q
}

// Verifier returns the verifier W
func (pvr *UserRecord) Verifier() []byte {
	return pvr.w
}

// QFromNonExistentUser builds q following the draft for a failed database lookup
// TODO : how should the case be handled in which the database entry does not exist ?
//  hash out q here or require it from database ?
// func (pvr *UserRecord) QFromNonExistentUser(prefix, username, databaseSeed []byte) error {
//	cipher := ciphersuite.New(nil)
//	// Check if identifier is not empty
//
//	// Check seed randomness
//
//	// Hashing
//	pvr.q = cipher.Hash(prefix, username, databaseSeed)
//
//	return nil
// }

// SetVerifier inserts the given verifier into the UserRecord, and therefore finishes its setup
func (pvr *UserRecord) SetVerifier(w []byte) {
	pvr.w = w
}
