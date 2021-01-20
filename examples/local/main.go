//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package main

import (
	"log"
	"net/http"

	"github.com/foomo/simplecert"
)

// This example demonstrates how spin up a simple HTTPS webserver for local development, with a locally trusted certificate.
// The mkcert (https://github.com/FiloSottile/mkcert) util must be installed for this to work, the generated certificates will be valid for 10 years.
// Caution: simplecert will automatically add an entry to your /etc/hosts to point the specified domain(s) to localhost!
func main() {

	// handle incoming HTTP request via the
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	// start the server and log the error if it crashes
	log.Fatal(simplecert.ListenAndServeTLSLocal(
		":443",
		nil, // <- passing a nil handler will use the http.DefaultServeMux, analogous to the standard library API
		nil, // <- passing nil for the cleanup function will cause your program to exit when receiving an interrupt signal
		"myawesomewebsite.com",
		"sub.myawesomewebsite.com",
	))
}
