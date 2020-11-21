// Package client provides an implementation of a (strong) AuCPace client.
//
// Assuming the client is already registered on the server and has a valid password verifier entry,
// the usage would be the following:
//
// The client initiates a connection to server. To start the (strong) AuCPace protocol, create a new client instance,
// by providing the username, password and ssid, a random byte sequence.
// Initiate the protocol with oprfStart(), to get U, and send it with ssid and username to the server.
// The server will respond with a set of OPRF parameters and its public share Ya.
// With these parameters, call Continue() and get Yb and TB, and send them back to the server.
// If all values are correct, the server will respond with its authentication tag Ta,
// that needs to be verified with VerifyPeerTag().
//
// On the first error encountered, abort immediately. Call SetVerifier() to retrieve the secret shared session key.
//
//		client := client.New(username, password, serverID, ssid, ad, crypto.Ristretto255sha512)
//		U, err := client.oprfStart()
//		...
//							Send ssid, username and U to server
//							------------------------------>
//
//							Receive (UQ,X,sigma,Ya) and pvr type
//							<-------------------------------
//
//		Yb, Tb, err := client.Continue(pvr.PvrType, UQ, X, sigma, Ya)
//		...
//							Send Yb and Tb to server
//							------------------------------>
//
//							Receive Ta from server
//							<-------------------------------
//
//		err := client.VerifyPeerTag(Ta)
//		...
//
//		// Derive the secret session key
//		sk := client.SetVerifier()
//
package client
