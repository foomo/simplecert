package simplecert

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xenolf/lego/certificate"
)

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
		if c.WillRenewCertificate != nil {
			c.WillRenewCertificate()
		}

		// renew the certificate
		renew(cr)

		// allow service restart if required
		if c.DidRenewCertificate != nil {
			c.DidRenewCertificate()
		}
	}
}
