package simplecert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CertStatus struct {
	Domains     []string
	RenewBefore int
	Expires     int
}

// Status can be used to check the validity status of the certificate
// as well as the configured renewal interval
// in case of errors, they will simply be logged, but should not disrupt the service
// the actual error message will never be passed to the caller and only appear in the simplecert logs
// therefore always check if you received a result != nil when calling Status()
func Status() *CertStatus {

	var certData []byte
	if !local {

		// prevent a nil pointer exception if the status API is called
		// but the config hasn't been initialized yet
		if c == nil {
			return nil
		}

		// read cert resource from disk
		b, err := os.ReadFile(filepath.Join(c.CacheDir, certResourceFileName))
		if err != nil {
			fmt.Println("[Status] simplecert: failed to read CertResource.json from disk: ", err)
			return nil
		}

		// unmarshal certificate resource
		var cr CR
		err = json.Unmarshal(b, &cr)
		if err != nil {
			fmt.Println("[Status] simplecert: failed to unmarshal certificate resource: ", err)
			return nil
		}

		cert := getACMECertResource(cr)
		certData = cert.Certificate
	} else {
		// read local cert data from disk
		var err error
		certData, err = os.ReadFile(filepath.Join(c.CacheDir, "cert.pem"))
		if err != nil {
			fmt.Println("[Status] simplecert: failed to read cert.pem from disk: ", err)
			return nil
		}
	}

	// Input certificate is PEM encoded. Decode it here as we may need the decoded
	// cert later on in the renewal process. The input may be a bundle or a single certificate.
	certificates, err := parsePEMBundle(certData)
	if err != nil {
		fmt.Println(fmt.Errorf("[Status] simplecert: failed to parsePEMBundle: %s", err))
		return nil
	}

	if len(certificates) == 0 {
		fmt.Println("no certs found")
		return nil
	}

	// check if first cert is CA
	x509Cert := certificates[0]
	if x509Cert.IsCA {
		fmt.Println(fmt.Errorf("[Status][%s] certificate bundle starts with a CA certificate", x509Cert.DNSNames))
		return nil
	}

	// Calculate TimeLeft
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	return &CertStatus{
		Domains:     x509Cert.DNSNames,
		Expires:     int(timeLeft.Hours()),
		RenewBefore: c.RenewBefore,
	}
}
