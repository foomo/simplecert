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
	"strings"

	"github.com/xenolf/lego/providers/dns"

	"github.com/xenolf/lego/certcrypto"
	"github.com/xenolf/lego/challenge/http01"
	"github.com/xenolf/lego/challenge/tlsalpn01"
	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/registration"
)

/*
 *	ACMEClient
 */

func createClient(u SSLUser) lego.Client {

	// create lego config
	config := lego.NewConfig(&u)
	config.CADirURL = c.DirectoryURL
	config.Certificate.KeyType = certcrypto.RSA4096

	// Create a new client instance
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to create client", err)
	}

	log.Println("[INFO] simplecert: client creation complete")

	// -------------------------------------------
	// HTTP & TLS Challenges
	// -------------------------------------------

	httpSlice := strings.Split(c.HTTPAddress, ":")
	if len(httpSlice) != 2 {
		log.Fatal("[FATAL] simplecert: invalid HTTP address: ", c.HTTPAddress)
	}
	tlsSlice := strings.Split(c.TLSAddress, ":")
	if len(tlsSlice) != 2 {
		log.Fatal("[FATAL] simplecert: invalid TLS address: ", c.TLSAddress)
	}

	// Set Endpoints
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(httpSlice[0], httpSlice[1]))
	if err != nil {
		log.Fatal("[FATAL] simplecert: setting http challenge provider failed: ", err)
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(tlsSlice[0], tlsSlice[1]))
	if err != nil {
		log.Fatal("[FATAL] simplecert: setting tls challenge provider failed: ", err)
	}

	// -------------------------------------------
	// DNS Challenge
	// -------------------------------------------

	if c.DNSProvider != "" {
		p, err := dns.NewDNSChallengeProviderByName(c.DNSProvider)
		if err != nil {
			log.Fatal("[FATAL] simplecert: invalid dns provider specified in config: ", err)
		}

		client.Challenge.SetDNS01Provider(p)
		if err != nil {
			log.Fatal("[FATAL] simplecert: setting dns challenge provider failed: ", err)
		}
	}

	// register if necessary
	if u.Registration == nil {

		// Register Client and agree to TOS
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to register client: ", err)
		}
		u.Registration = reg
		log.Println("[INFO] simplecert: client registration complete: ", client)
		saveUserToDisk(u, c.CacheDir)
	}

	return *client
}
