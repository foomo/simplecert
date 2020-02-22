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

	"github.com/go-acme/lego/v3/challenge/tlsalpn01"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/challenge/http01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/go-acme/lego/v3/registration"
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
		return lego.Client{}, fmt.Errorf("simplecert: failed to create client: %s", err)
	}

	log.Println("[INFO] simplecert: client creation complete")

	// -------------------------------------------
	// DNS Challenge
	// -------------------------------------------

	if c.DNSProvider != "" {
		p, err := dns.NewDNSChallengeProviderByName(c.DNSProvider)
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting DNS provider specified in config: %s", err)
		}

		err = client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting DNS challenge provider failed: %s", err)
		}

		log.Println("[INFO] simplecert: set DNS challenge")
	}

	// -------------------------------------------
	// HTTP Challenges
	// -------------------------------------------

	if c.HTTPAddress != "" {
		httpSlice := strings.Split(c.HTTPAddress, ":")
		if len(httpSlice) != 2 {
			return *client, fmt.Errorf("simplecert: invalid HTTP address: %s", c.HTTPAddress)
		}
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(httpSlice[0], httpSlice[1]))
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting HTTP challenge provider failed: %s", err)
		}

		log.Println("[INFO] simplecert: set HTTP challenge")
	}

	// -------------------------------------------
	// TLS Challenges
	// -------------------------------------------

	if c.TLSAddress != "" {
		tlsSlice := strings.Split(c.TLSAddress, ":")
		if len(tlsSlice) != 2 {
			return *client, fmt.Errorf("simplecert: invalid TLS address: %s", c.TLSAddress)
		}
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(tlsSlice[0], tlsSlice[1]))
		if err != nil {
			return *client, fmt.Errorf("simplecert: setting TLS challenge provider failed: %s", err)
		}

		log.Println("[INFO] simplecert: set TLS challenge")
	}

	if c.DNSProvider == "" && c.TLSAddress == "" && c.HTTPAddress == "" {
		return *client, fmt.Errorf("simplecert: you must specify at least one of the challenge types: dns, http or tls")
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
