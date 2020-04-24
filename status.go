package simplecert

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"
)

const errInternal = "internal error"

// Status can be used to check the validity status of the certificate
// as well as the configured renewal interval
// in case of errors, they will simply be logged, but should not disrupt the service
// the actual error message will never be passed to the caller and only appear in the simplecert logs
func Status() string {

	// read cert resource from disk
	b, err := ioutil.ReadFile(filepath.Join(c.CacheDir, certResourceFileName))
	if err != nil {
		fmt.Println("[Status] simplecert: failed to read CertResource.json from disk: ", err)
		return errInternal
	}

	// unmarshal certificate resource
	var cr CR
	err = json.Unmarshal(b, &cr)
	if err != nil {
		fmt.Println("[Status] simplecert: failed to unmarshal certificate resource: ", err)
		return errInternal
	}

	cert := getACMECertResource(cr)

	// Input certificate is PEM encoded. Decode it here as we may need the decoded
	// cert later on in the renewal process. The input may be a bundle or a single certificate.
	certificates, err := parsePEMBundle(cert.Certificate)
	if err != nil {
		fmt.Println(fmt.Errorf("simplecert: failed to parsePEMBundle: %s", err))
		return errInternal
	}

	if len(certificates) == 0 {
		fmt.Println("no certs found")
		return errInternal
	}

	// check if first cert is CA
	x509Cert := certificates[0]
	if x509Cert.IsCA {
		fmt.Println(fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", cert.Domain))
		return errInternal
	}

	// iterate over all certs?
	fmt.Println("num certificates:", len(certificates))

	// Calculate TimeLeft
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	return fmt.Sprintf("[%s] acme: %d hours remaining, renewBefore: %d", cert.Domain, int(timeLeft.Hours()), int(c.RenewBefore))
}
