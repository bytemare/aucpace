package aucpace

import (
	"bytes"
	"fmt"

	"github.com/bytemare/aucpace/verifier"
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
)

// Associated data
var ad []byte = nil

// The user record to be used for registration and authentication
var pvr *verifier.UserRecord

func ExampleAuCPaceRegistration() {
	serverID := []byte("server")
	username := []byte("user")
	password := []byte("password")

	clientParams := &Parameters{
		SSID:     nil,
		AD:       ad,
		SNI:      serverID,
		UserID:   username,
		Secret:   password,
		Encoding: encoding.JSON,
	}

	/*
		A client wants to play (strong) AuCPace with the server, identified by sni
	*/
	client, err := Registration.Client(clientParams, nil)
	if err != nil {
		panic(err)
	}

	message1, err := client.Register(nil)
	if err != nil {
		panic(err)
	}

	// Set up server
	//
	serverParams := &Parameters{
		AD:       ad,
		SNI:      serverID,
		Encoding: encoding.JSON,
	}

	server, err := Registration.Server(serverParams, nil)
	if err != nil {
		panic(err)
	}

	// The server receives the message, and looks up its database for a client record.
	// For this proof-of-concept, let's register a dummy fresh user record on the server.
	csp, err := cryptotools.ReadCiphersuite(server.EncodedParameters())
	if err != nil {
		panic(err)
	}
	pvr, err = NewUserRecord(username, csp)
	if err != nil {
		panic(err)
	}

	server.SetUserRecord(pvr)

	// Give the server the client message message1, and return message2
	message2, err := server.Register(message1)
	if err != nil {
		panic(err)
	}

	// Give the client the server's response. Here, the client builds its verifier and puts it in message3, to be send
	// to the server.
	message3, err := client.Register(message2)
	if err != nil {
		panic(err)
	}

	// The server receives the client's verifier and stores it in the user's password verifier record
	_, _ = server.Register(message3)

	// The client has now its verifier stored on the server
	if pvr.Verifier() != nil {
		fmt.Println("A verifier was registered on the server.")
	} else {
		fmt.Println("Warning: no verifier was registered but no error has been raised before.")
	}
	// Output: A verifier was registered on the server.
}

func ExampleAuCPaceAuthentication() {
	serverID := []byte("server")
	username := []byte("user")
	password := []byte("password")

	// Suppose a client record was setup earlier and stored in a database
	ExampleAuCPaceRegistration()

	clientParams := &Parameters{
		SSID:   nil,
		AD:     ad,
		SNI:    serverID,
		UserID: username,
		Secret: password,
	}

	/*
		let's say the client wants to authenticate to the server
	*/
	//client := aucpace.New(pake.KeyExchange, aucpace.Client, nil, nil, ad, serverID, username, password)
	client, err := Authentication.Client(clientParams, nil)
	if err != nil {
		panic(err)
	}

	message1, err := client.Authenticate(nil)
	if err != nil {
		panic(err)
	}

	//
	serverParams := &Parameters{
		SSID:   nil,
		AD:     ad,
		SNI:    serverID,
		UserID: username,
		Secret: password,
	}

	// server := aucpace.New(pake.KeyExchange, aucpace.Server, nil, nil, ad, serverID, nil, nil)
	server, err := Authentication.Server(serverParams, nil)
	if err != nil {
		panic(err)
	}

	if err := server.SetUserRecord(pvr); err != nil {
		panic(err)
	}

	//
	message2, err := server.Authenticate(message1)
	if err != nil {
		panic(err)
	}

	// Client finishes CPace and authenticates to the server
	message3, err := client.Authenticate(message2)
	if err != nil {
		panic(err)
	}

	// Server verifies client authentication tag and sends back its own
	message4, err := server.Authenticate(message3)
	if err != nil {
		panic(err)
	}

	serverSessionKey := server.SessionKey()

	// Client checks server authentication tag
	_, err = client.Authenticate(message4)
	if err != nil {
		panic(err)
	}

	clientSessionKey := client.SessionKey()

	if bytes.Equal(clientSessionKey, serverSessionKey) {
		fmt.Println("Success ! Both parties share the same secret session key !")
	} else {
		fmt.Println("Failed. Client and server keys are different.")
	}
	// Output: A verifier was registered on the server.
	// Success ! Both parties share the same secret session key !
}
