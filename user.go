//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

const sslUserFileName = "SSLUser.json"

/*
 *	SSLUser
 */

// SSLUser implements the ACME User interface
type SSLUser struct {
	Email        string
	Registration *registration.Resource
	Key          *rsa.PrivateKey
}

// GetEmail returns the users email
func (u SSLUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the users registration resource
func (u SSLUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the users private key
func (u SSLUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// get SSL User from cacheDir or create a new one
func getUser() (SSLUser, error) {

	// no cached cert. start from scratch
	var u SSLUser

	// do we have a user?
	b, err := os.ReadFile(filepath.Join(c.CacheDir, sslUserFileName))
	if err == nil {
		// user exists. load
		err = json.Unmarshal(b, &u)
		if err != nil {
			return u, fmt.Errorf("simplecert: failed to unmarshal SSLUser: %s", err)
		}
	} else {
		// create private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return u, fmt.Errorf("simplecert: failed to generate private key: %s", err)
		}

		// Create new user
		u = SSLUser{
			Email: c.SSLEmail,
			Key:   privateKey,
		}
	}

	return u, nil
}

// save the user on disk
// fatals on error
func saveUserToDisk(u SSLUser, cacheDir string) {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to marshal user: ", err)
	}
	err = os.WriteFile(filepath.Join(c.CacheDir, sslUserFileName), b, c.CacheDirPerm)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to write user to disk: ", err)
	}
}
