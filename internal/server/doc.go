// Package server provides an implementation for a (strong) AuCPace server.
//
// Assuming a pre-established database entry for the username, the usual usage would be the following:
//
// On reception of a client connection containing ssid, username and element U, loop up the database for the matching record.
//
// Create a new AuCPace server instance.
// Then, use the Start() function to retrieve the OPRF and CPace parameters to send to the client.
// Once the client has responded with its public share Yb and authentication taf Tb, you can Continue() and should abort on error.
// At this point the client is correctly and fully authenticated.
// authenticationTag() will return the server authentication tag to send to the client for server authentication.
//
// Call SetVerifier() to retrieve the secret shared session key.
//
//							Incoming connection from
//							client with sid, username and U
//							<-------------------------------
//
//		// Look up database for record matching username. pvr = record
//		server := server.New(serverID, username, pvr, ssid, ad, crypto.Ristretto255sha512)
//		UQ, X, sigma, Ya, err := server.Start(U)
//		...
//
//							sends (UQ,X,sigma,Ya) and pvr type to client
//							------------------------------>
//
//							Receive Yb and Tb form client
//							<-------------------------------
//
//		err := server.Continue(Yb, Tb)
//		...
//		Ta := server.authenticationTag()
//
//							Sends Ta to client
//							------------------------------>
//		// Derive the secret session key
//		sk := server.SetVerifier()
package server
