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
	"io/ioutil"
	"log"

	"github.com/xenolf/lego/acme"
)

/*
 *	SSLUser
 */

// SSLUser implements the ACME User interface
type SSLUser struct {
	Email        string
	Registration *acme.RegistrationResource
	Key          *rsa.PrivateKey
}

// GetEmail returns the users email
func (u SSLUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the users registration resource
func (u SSLUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

// GetPrivateKey returns the users private key
func (u SSLUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// get SSL User from cacheDir or create a new one
func getUser() SSLUser {

	// no cached cert. start from scratch
	var u SSLUser

	// do we have a user?
	b, err := ioutil.ReadFile(c.CacheDir + "/SSLUser.json")
	if err == nil {
		// user exists. load
		err = json.Unmarshal(b, &u)
		if err != nil {
			log.Fatal("[FATAL] failed to unmarshal SSLUser: ", err)
		}
	} else {
		// create private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}

		// Create new user
		u = SSLUser{
			Email: c.SSLEmail,
			Key:   privateKey,
		}
	}

	return u
}

// save the user on disk
// fatals on error
func saveUserToDisk(u SSLUser, cacheDir string) {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		log.Fatal("[FATAL] failed to marshal user: ", err)
	}
	err = ioutil.WriteFile(c.CacheDir+"/SSLUser.json", b, c.CacheDirPerm)
	if err != nil {
		log.Fatal("[FATAL] failed to write user to disk: ", err)
	}
}
