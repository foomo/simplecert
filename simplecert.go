//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// Init obtains a new LetsEncrypt cert for the specified domains if there is none in cacheDir
// or loads an existing one. Certs will be auto renewed in the configured interval.
// 1. Check if we have a cached certificate, if yes kickoff renewal routine and return
// 2. No Cached Certificate found - make sure the supplied cacheDir exists
// 3. Create a new SSLUser and ACME Client
// 4. Obtain a new certificate
// 5. Save To Disk
// 6. Kickoff Renewal Routine
func Init(cfg *Config) (*CertReloader, error) {

	// validate config
	err := CheckConfig(cfg)
	if err != nil {
		return nil, err
	}

	// config ok.
	// update global config
	c = cfg

	// open logfile handle
	logFile, err := os.OpenFile(filepath.Join(c.CacheDir, "simplecert.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to create logfile", err)
	}

	// configure log pkg to log to stdout and into the logfile
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	// do we have a certificate in cacheDir?
	if certCached(c.CacheDir) {

		/*
		 *	Cert Found. Load it
		 */
		log.Println("[INFO] simplecert: found cert in cacheDir")

		// read cert resource from disk
		b, err := ioutil.ReadFile(c.CacheDir + "/CertResource.json")
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to read CertResource.json from disk: ", err)
		}

		// unmarshal certificate resource
		var cr CR
		err = json.Unmarshal(b, &cr)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to unmarshal certificate resource")
		}

		cert := getACMECertResource(cr)

		// renew cert if necessary
		renew(cert)

		// kickoff renewal routine
		go renewalRoutine(cert)

		return NewCertReloader(c.CacheDir+"/cert.pem", c.CacheDir+"/key.pem", logFile)
	}

	/*
	 *	No Cert Found. Register a new one
	 */

	// make sure the cacheDir exists
	ensureCacheDirExists(c.CacheDir)

	// get ACME Client
	client := createClient(getUser())

	// Obtain a new certificate
	// The acme library takes care of completing the challenges to obtain the certificate(s).
	// The domains must resolve to this machine or you have to use the DNS challenge.
	cert, failures := client.ObtainCertificate(c.Domains, true, nil, false)
	if len(failures) > 0 {
		log.Println("[INFO] simplecert: failed to verify ", len(failures), " domains")
		// At least one domain failed to verify, but others may have succeeded.
		// If there were any failures, no certificate will be returned.
		for domain, err := range failures {
			log.Printf("[%s] %v", domain, err)
		}
	}

	log.Println("[INFO] simplecert: client obtained cert for domain: ", cert.Domain)

	// Save cert to disk
	err = saveCertToDisk(cert, c.CacheDir)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to write cert to disk")
	}

	log.Println("[INFO] simplecert: wrote new cert to disk!")

	// kickoff renewal routine
	go renewalRoutine(&cert)

	return NewCertReloader(c.CacheDir+"/cert.pem", c.CacheDir+"/key.pem", logFile)
}
