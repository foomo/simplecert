//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"log"

	"github.com/xenolf/lego/acme"
)

/*
 *	ACMEClient
 */

func createClient(u SSLUser) acme.Client {

	// Create a new client instance
	client, err := acme.NewClient(c.DirectoryURL, &u, acme.RSA4096)
	if err != nil {
		log.Fatal("[FATAL] failed to create client", err)
	}

	log.Println("[INFO] client creation complete")

	// Set Endpoints
	client.SetHTTPAddress(c.HTTPAddress)
	client.SetTLSAddress(c.TLSAddress)

	// register if necessary
	if u.Registration == nil {

		// Register Client
		reg, err := client.Register()
		if err != nil {
			log.Fatal("[FATAL] failed to register client: ", err)
		}
		u.Registration = reg
		log.Println("[INFO] client registration complete: ", client)
		saveUserToDisk(u, c.CacheDir)

		// The client has a URL to the current Let's Encrypt Subscriber
		// Agreement. The user will need to agree to it.
		err = client.AgreeToTOS()
		if err != nil {
			log.Fatal("[FATAL] failed to agreeToTOS: ", err)
		}
		log.Println("[INFO] client agreeToTOS complete")
	}

	return *client
}
