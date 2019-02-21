//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

/*
 *	CertReloader
 */

// CertReloader manages a hot reload of a new cert
type CertReloader struct {
	sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

// NewCertReloader returns a new CertReloader instance
func NewCertReloader(certPath, keyPath string, logFile *os.File) (*CertReloader, error) {

	// init reloader
	reloader := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}

	// Load keypair
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	reloader.cert = &cert

	// kickoff routine for handling singals
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGABRT)
		for sig := range sigChan {
			if sig == syscall.SIGHUP {
				log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", certPath, keyPath)
				if err := reloader.maybeReload(); err != nil {
					log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)

					// rollback files from backup dir
					// restore private key
					err = os.Rename(c.CacheDir+"/backup-"+backupDate+"/key.pem", c.CacheDir+"/key.pem")
					if err != nil {
						log.Fatal("[FATAL] simplecert: failed to move key into backup dir: ", err)
					}

					// restore certificate
					err = os.Rename(c.CacheDir+"/backup-"+backupDate+"/key.pem", c.CacheDir+"/cert.pem")
					if err != nil {
						log.Fatal("[FATAL] simplecert: failed to move cert into backup dir: ", err)
					}

					err = os.Remove(c.CacheDir + "/backup-" + backupDate)
					if err != nil {
						log.Fatal("[FATAL] simplecert: failed to remove backup dir: ", err)
					}
				}
			} else {
				// cleanup
				err := logFile.Close()
				if err != nil {
					log.Fatal("[FATAL] simplecert: failed to close logfile handle: ", err)
				}
				log.Println("[INFO] simplecert: closed logfile handle")
				os.Exit(0)
			}
		}
	}()

	return reloader, nil
}

func (reloader *CertReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(reloader.certPath, reloader.keyPath)
	if err != nil {
		return err
	}
	reloader.Lock()
	defer reloader.Unlock()
	reloader.cert = &newCert
	return nil
}

// GetCertificateFunc is needed for hot reload
func (reloader *CertReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		reloader.RLock()
		defer reloader.RUnlock()
		return reloader.cert, nil
	}
}
