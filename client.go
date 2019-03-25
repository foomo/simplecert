//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-acme/lego/providers/dns"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/challenge/http01"
	"github.com/go-acme/lego/challenge/tlsalpn01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
)

/*
 *	ACMEClient
 */

func createClient(u SSLUser) (lego.Client, error) {

	// create lego config
	config := lego.NewConfig(&u)
	config.CADirURL = c.DirectoryURL
	config.Certificate.KeyType = certcrypto.RSA4096

	// Create a new client instance
	client, err := lego.NewClient(config)
	if err != nil {
		return *client, fmt.Errorf("simplecert: failed to create client: %s", err)
	}

	log.Println("[INFO] simplecert: client creation complete")

	// -------------------------------------------
	// HTTP & TLS Challenges
	// -------------------------------------------

	httpSlice := strings.Split(c.HTTPAddress, ":")
	if len(httpSlice) != 2 {
		return *client, fmt.Errorf("simplecert: invalid HTTP address: %s", c.HTTPAddress)
	}
	tlsSlice := strings.Split(c.TLSAddress, ":")
	if len(tlsSlice) != 2 {
		return *client, fmt.Errorf("simplecert: invalid TLS address: %s", c.TLSAddress)
	}

	// Set Endpoints
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(httpSlice[0], httpSlice[1]))
	if err != nil {
		return *client, fmt.Errorf("simplecert: setting HTTP challenge provider failed: %s", err)
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(tlsSlice[0], tlsSlice[1]))
	if err != nil {
		return *client, fmt.Errorf("simplecert: setting TLS challenge provider failed: %s", err)
	}

	// -------------------------------------------
	// DNS Challenge
	// -------------------------------------------

	if c.DNSProvider != "" {
		p, err := dns.NewDNSChallengeProviderByName(c.DNSProvider)
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting DNS provider specified in config: %s", err)
		}

		client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting DNS challenge provider failed: %s", err)
		}
	}

	// register if necessary
	if u.Registration == nil {

		// Register Client and agree to TOS
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return *client, fmt.Errorf("simplecert: failed to register client: %s", err)
		}
		u.Registration = reg
		log.Println("[INFO] simplecert: client registration complete: ", client)
		saveUserToDisk(u, c.CacheDir)
	}

	return *client, nil
}
