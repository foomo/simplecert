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
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-acme/lego/v3/certificate"
)

func renew(cert *certificate.Resource) error {

	// Input certificate is PEM encoded. Decode it here as we may need the decoded
	// cert later on in the renewal process. The input may be a bundle or a single certificate.
	certificates, err := parsePEMBundle(cert.Certificate)
	if err != nil {
		return fmt.Errorf("simplecert: failed to parsePEMBundle: %s", err)
	}

	// check if first cert is CA
	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", cert.Domain)
	}

	// Calculate TimeLeft
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	log.Printf("[INFO][%s] acme: %d hours remaining, renewBefore: %d\n", cert.Domain, int(timeLeft.Hours()), int(c.RenewBefore))

	// Check against renewBefore
	if int(timeLeft.Hours()) <= int(c.RenewBefore) {

		log.Println("[INFO] simplecert: renewing cert...")

		// allow graceful shutdown of running services if required
		if c.WillRenewCertificate != nil {
			c.WillRenewCertificate()
		}

		u, err := getUser()
		if err != nil {
			return fmt.Errorf("simplecert: failed to get acme user: %s", err)
		}

		// get ACME Client
		client, err := createClient(u)
		if err != nil {
			return fmt.Errorf("simplecert: failed to create lego.Client: %s", err)
		}

		// start renewal
		// bundle CA with certificate to avoid "transport: x509: certificate signed by unknown authority" error
		cert, err := client.Certificate.Renew(*cert, true, false)
		if err != nil {
			return fmt.Errorf("simplecert: failed to renew cert: %s", err)
		}

		// if we made it here we got a new cert
		// backup old cert and key
		// create a new directory for those in cacheDir, named backup-{currentDate}-{currentTime}
		backupDate = time.Now().Format("2006-January-02-1504")
		err = os.MkdirAll(filepath.Join(c.CacheDir, "backup-"+backupDate), c.CacheDirPerm)
		if err != nil {
			return fmt.Errorf("simplecert: failed to create backup dir: %s", err)
		}

		// backup private key
		err = os.Rename(filepath.Join(c.CacheDir, keyFileName), filepath.Join(c.CacheDir, "backup-"+backupDate, keyFileName))
		if err != nil {
			return fmt.Errorf("simplecert: failed to move key into backup dir: %s", err)
		}

		// backup certificate
		err = os.Rename(filepath.Join(c.CacheDir, certFileName), filepath.Join(c.CacheDir, "backup-"+backupDate, keyFileName))
		if err != nil {
			return fmt.Errorf("simplecert: failed to move cert into backup dir: %s", err)
		}

		// Save new cert to disk
		err = saveCertToDisk(cert, c.CacheDir)
		if err != nil {
			return fmt.Errorf("simplecert: failed to write new cert to disk: %s", err)
		}

		log.Println("[INFO] simplecert: wrote new cert to disk!")

		log.Println("[INFO] triggering reload via SIGHUP")

		// trigger reload by sending our process a SIGHUP
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			return fmt.Errorf("simplecert: failed to get process by PID: %s", err)
		}

		// send signal
		err = p.Signal(syscall.SIGHUP)
		if err != nil {
			return fmt.Errorf("simplecert: failed to send SIGHUP to our process: %s", err)
		}

		// allow service restart if required
		if c.DidRenewCertificate != nil {
			c.DidRenewCertificate()
		}
	}

	return nil
}

// take care of checking the cert in the configured interval
// and renew if timeLeft is less than or equal to renewBefore
// when initially started, the certificate is checked against the thresholds and renewed if neccessary
func renewalRoutine(cr *certificate.Resource) {

	for {
		// sleep for duration of checkInterval
		time.Sleep(c.CheckInterval)

		// renew the certificate
		err := renew(cr)
		if err != nil { // something went wrong.

			// call handler if set
			if c.FailedToRenewCertificate != nil {
				c.FailedToRenewCertificate(err)
			} else {
				// otherwise fatal
				log.Fatal("[FATAL] failed to renew cert: ", err.Error())
			}
		}
	}
}
