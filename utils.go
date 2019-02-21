//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xenolf/lego/certificate"
)

// internal date of the backup to allow restoring in case of an error
// even if renewal happens just before midnight and restoring afterwards
var backupDate string

const localhost = "127.0.0.1"

/*
 *	Utils
 */

// parsePEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func parsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {

	var (
		certificates []*x509.Certificate
		certDERBlock *pem.Block
	)

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("No certificates were found while parsing the bundle")
	}

	return certificates, nil
}

func renew(cert *certificate.Resource) {

	// Input certificate is PEM encoded. Decode it here as we may need the decoded
	// cert later on in the renewal process. The input may be a bundle or a single certificate.
	certificates, err := parsePEMBundle(cert.Certificate)
	if err != nil {
		log.Fatal("[FATAL] simplecert: failed to parsePEMBundle: ", err)
	}

	// check if first cert is CA
	x509Cert := certificates[0]
	if x509Cert.IsCA {
		log.Fatalf("[%s] Certificate bundle starts with a CA certificate", cert.Domain)
	}

	// Calculate TimeLeft
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	log.Printf("[INFO][%s] acme: %d hours remaining, renewBefore: %d\n", cert.Domain, int(timeLeft.Hours()), int(c.RenewBefore))

	// Check against renewBefore
	if int(timeLeft.Hours()) <= int(c.RenewBefore) {

		log.Println("[INFO] simplecert: renewing cert...")

		// get ACME Client
		client := createClient(getUser())

		// start renewal
		// bundle CA with certificate to avoid "transport: x509: certificate signed by unknown authority" error
		cert, err := client.Certificate.Renew(*cert, true, false)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to renew cert: ", err)
		}

		// if we made it here we got a new cert
		// backup old cert and key
		// create a new directory for those in cacheDir, named backup-{currentDate}
		backupDate = time.Now().Format("2006-January-02")
		err = os.Mkdir(filepath.Join(c.CacheDir, "backup-"+backupDate), c.CacheDirPerm)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to create backup dir: ", err)
		}

		// backup private key
		err = os.Rename(filepath.Join(c.CacheDir, keyFileName), filepath.Join(c.CacheDir, "backup-"+backupDate, keyFileName))
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to move key into backup dir: ", err)
		}

		// backup certificate
		err = os.Rename(filepath.Join(c.CacheDir, certFileName), filepath.Join(c.CacheDir, "backup-"+backupDate, keyFileName))
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to move cert into backup dir: ", err)
		}

		// Save new cert to disk
		err = saveCertToDisk(cert, c.CacheDir)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to write new cert to disk")
		}

		log.Println("[INFO] simplecert: wrote new cert to disk! triggering reload via SIGHUP")

		// trigger reload by sending our process a SIGHUP
		err = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		if err != nil {
			log.Fatal("[FATAL] simplecert: failed to trigger reload of renewed certificate: ", err)
		}
	}
}

// take care of checking the cert in the configured interval
// and renew if timeLeft is less than or equal to renewBefore
// when initially started, the certificate is checked against the thresholds and renewed if neccessary
func renewalRoutine(cr *certificate.Resource) {

	for {
		// sleep for duration of checkInterval
		time.Sleep(c.CheckInterval)

		// allow graceful shutdown of running services if required
		c.WillRenewCertificate()

		// renew the certificate
		renew(cr)

		// allow service restart if required
		c.DidRenewCertificate()
	}
}

// cert exists in cacheDir?
func certCached(cacheDir string) bool {
	_, errCert := os.Stat(filepath.Join(cacheDir, certFileName))
	_, errKey := os.Stat(filepath.Join(cacheDir, keyFileName))
	if errCert == nil && errKey == nil {
		return true
	}
	return false
}

// ensures the cacheDir exists, fatals on error
func ensureCacheDirExists(cacheDir string) {
	log.Println("[INFO] simplecert: checking if cacheDir " + cacheDir + " exists...")

	// create cacheDir if necessary
	info, err := os.Stat(cacheDir)
	if err != nil {
		log.Println("[INFO] simplecert: cacheDir does not exist - creating it")
		err = os.MkdirAll(c.CacheDir, c.CacheDirPerm)
		if err != nil {
			log.Fatal("[FATAL] simplecert: could not create cacheDir: ", err)
		}
	} else {
		// exists. make sure its a directory
		if !info.IsDir() {
			log.Fatal("[FATAL] simplecert: cacheDir: expected a directory but got a file?!")
		}
	}
}

// Persist the certificate on disk
// this assumes that cacheDir exists
func saveCertToDisk(cert *certificate.Resource, cacheDir string) error {

	// JSON encode certificate resource
	// needs to be a CR otherwise the fields with the keys will be lost
	b, err := json.MarshalIndent(CR{
		Domain:            cert.Domain,
		CertURL:           cert.CertURL,
		CertStableURL:     cert.CertStableURL,
		PrivateKey:        cert.PrivateKey,
		Certificate:       cert.Certificate,
		IssuerCertificate: cert.IssuerCertificate,
		CSR:               cert.CSR,
	}, "", "  ")
	if err != nil {
		return err
	}

	// write certificate resource to disk
	err = ioutil.WriteFile(filepath.Join(cacheDir, certResourceFileName), b, c.CacheDirPerm)
	if err != nil {
		return err
	}

	// write certificate PEM to disk
	err = ioutil.WriteFile(filepath.Join(cacheDir, certFileName), cert.Certificate, c.CacheDirPerm)
	if err != nil {
		return err
	}

	// write private key PEM to disk
	err = ioutil.WriteFile(filepath.Join(cacheDir, keyFileName), cert.PrivateKey, c.CacheDirPerm)
	if err != nil {
		return err
	}

	return nil
}

// Redirect a request to HTTPS and strip www. subdomain
func Redirect(w http.ResponseWriter, req *http.Request) {

	// remove/add not default ports from req.Host
	target := "https://" + strings.TrimPrefix(req.Host, "www.") + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}

	fmt.Println("redirect: ", target, " ("+req.Host+")", "UserAgent:", req.UserAgent())
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

// runCommand executes the named command with the supplied arguments
// and fatals on error
func runCommand(cmd string, args ...string) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("[ERROR] failed to run command: ", cmd+strings.Join(args, " "))
		log.Fatal("[FATAL] simplecert: error: ", err, ", output: ", string(out))
	}
}
