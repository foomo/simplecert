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

	"github.com/go-acme/lego/v3/certificate"
)

const (
	logFileName          = "simplecert.log"
	certResourceFileName = "CertResource.json"
	certFileName         = "cert.pem"
	keyFileName          = "key.pem"
)

// Init obtains a new LetsEncrypt cert for the specified domains if there is none in cacheDir
// or loads an existing one. Certs will be auto renewed in the configured interval.
// 1. Check if we have a cached certificate, if yes kickoff renewal routine and return
// 2. No Cached Certificate found - make sure the supplied cacheDir exists
// 3. Create a new SSLUser and ACME Client
// 4. Obtain a new certificate
// 5. Save To Disk
// 6. Kickoff Renewal Routine
func Init(cfg *Config, cleanup func()) (*CertReloader, error) {

	// validate config
	err := CheckConfig(cfg)
	if err != nil {
		return nil, err
	}

	// config ok.
	// update global config
	c = cfg

	// make sure the cacheDir exists
	ensureCacheDirExists(c.CacheDir)

	// open logfile handle
	logFile, err := os.OpenFile(filepath.Join(c.CacheDir, logFileName), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to create logfile: ", err)
	}

	// configure log pkg to log to stdout and into the logfile
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	if c.Local {

		// update the cachedir path
		// certs used in local mode are stored in the "local" subfolder
		// to avoid overwriting a production certificate
		c.CacheDir = filepath.Join(c.CacheDir, "local")

		// make sure the cacheDir/local folder exists
		ensureCacheDirExists(c.CacheDir)

		var (
			certFilePath = filepath.Join(c.CacheDir, certFileName)
			keyFilePath  = filepath.Join(c.CacheDir, keyFileName)
		)

		// check if a local cert is already cached
		if certCached(c.CacheDir) {

			// cert cached! Did the domains change?
			// If the domains have been modified we need to generate a new certificate
			if domainsChanged(certFilePath, keyFilePath) {
				log.Println("[INFO] cert cached but domains have changed. generating a new one...")
				createLocalCert(certFilePath, keyFilePath)
			}
		} else {

			// nothing there yet. create a new one
			createLocalCert(certFilePath, keyFilePath)
		}

		// create entries in /etc/hosts if necessary
		if c.UpdateHosts {
			updateHosts()
		}

		// return a cert reloader for the local cert
		return NewCertReloader(certFilePath, keyFilePath, logFile, cleanup)
	}

	var (
		certFilePath = filepath.Join(c.CacheDir, certFileName)
		keyFilePath  = filepath.Join(c.CacheDir, keyFileName)
	)

	// do we have a certificate in cacheDir?
	if certCached(c.CacheDir) {

		/*
		 *	Cert Found. Load it
		 */

		if domainsChanged(certFilePath, keyFilePath) {
			log.Println("[INFO] domains have changed. Obtaining a new certificate...")
			goto obtainNewCert
		}

		log.Println("[INFO] simplecert: found cert in cacheDir")

		// read cert resource from disk
		b, err := ioutil.ReadFile(filepath.Join(c.CacheDir, certResourceFileName))
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to read CertResource.json from disk: ", err)
		}

		// unmarshal certificate resource
		var cr CR
		err = json.Unmarshal(b, &cr)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to unmarshal certificate resource: ", err)
		}

		cert := getACMECertResource(cr)

		// renew cert if necessary
		errRenew := renew(cert, cfg)
		if errRenew != nil {
			log.Fatal("[FATAL] failed to renew cached cert on startup: ", errRenew)
		}

		// kickoff renewal routine
		go renewalRoutine(cert, cfg)

		return NewCertReloader(certFilePath, keyFilePath, logFile, cleanup)
	}

obtainNewCert:

	/*
	 *	No Cert Found. Register a new one
	 */

	u, err := getUser()
	if err != nil {
		log.Fatal("[FATAL] failed to get ACME user: ", err)
	}

	// get ACME Client
	client, err := createClient(u)
	if err != nil {
		log.Fatal("[FATAL] failed to create lego.Client: ", err)
	}

	// bundle CA with certificate to avoid "transport: x509: certificate signed by unknown authority" error
	request := certificate.ObtainRequest{
		Domains: c.Domains,
		Bundle:  true,
	}

	// Obtain a new certificate
	// The acme library takes care of completing the challenges to obtain the certificate(s).
	// The domains must resolve to this machine or you have to use the DNS challenge.
	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to obtain cert: ", err)
	}

	log.Println("[INFO] simplecert: client obtained cert for domain: ", cert.Domain)

	// Save cert to disk
	err = saveCertToDisk(cert, c.CacheDir)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to write cert to disk")
	}

	log.Println("[INFO] simplecert: wrote new cert to disk!")

	// kickoff renewal routine
	go renewalRoutine(cert, cfg)

	return NewCertReloader(certFilePath, keyFilePath, logFile, cleanup)
}
