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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/foomo/tlsconfig"
)

// internal date of the backup to allow restoring in case of an error
// even if renewal happens just before midnight and restoring afterwards
var backupDate string

const localhost = "127.0.0.1"

/*
 *	Utils
 */

// ListenAndServeTLSCustom allows to specify the simplecert and TLS configuration
// and does not redirect the traffic arriving at port 80
func ListenAndServeTLSCustom(addr string, handler http.Handler, cfg *Config, tlsconf *tls.Config, domains ...string) error {

	certReloader, err := Init(cfg)
	if err != nil {
		log.Fatal("[FATAL] simplecert init failed: ", err)
	}

	// now set GetCertificate to the reloaders GetCertificateFunc to enable hot reload
	tlsconf.GetCertificate = certReloader.GetCertificateFunc()

	// init server
	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsconf,
		Handler:   handler,
	}

	log.Println("serving: https://" + cfg.Domains[0])

	// lets go
	return s.ListenAndServeTLS("", "")
}

// ListenAndServeTLSLocal is a util to use simplecert for local development
func ListenAndServeTLSLocal(addr string, handler http.Handler, domains ...string) error {

	cfg := Default
	cfg.Domains = domains
	cfg.CacheDir = "simplecert"
	cfg.Local = true
	certReloader, err := Init(cfg)
	if err != nil {
		log.Fatal("[FATAL] simplecert init failed: ", err)
	}

	// redirect HTTP to HTTPS
	log.Println("starting HTTP Listener on Port 80")
	go http.ListenAndServe(":80", http.HandlerFunc(Redirect))

	// init strict tlsConfig with certReloader
	tlsconf := tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

	// now set GetCertificate to the reloaders GetCertificateFunc to enable hot reload
	tlsconf.GetCertificate = certReloader.GetCertificateFunc()

	// init server
	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsconf,
		Handler:   handler,
	}

	log.Println("serving: https://" + cfg.Domains[0])

	// lets go
	return s.ListenAndServeTLS("", "")
}

// ListenAndServeTLS is a util to use simplecert in production
func ListenAndServeTLS(addr string, handler http.Handler, mail string, domains ...string) error {

	cfg := Default
	cfg.Domains = domains
	cfg.CacheDir = "simplecert"
	cfg.SSLEmail = mail
	certReloader, err := Init(cfg)
	if err != nil {
		log.Fatal("[FATAL] simplecert init failed: ", err)
	}

	// redirect HTTP to HTTPS
	log.Println("starting HTTP Listener on Port 80")
	go http.ListenAndServe(":80", http.HandlerFunc(Redirect))

	// init strict tlsConfig with certReloader
	tlsconf := tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

	// now set GetCertificate to the reloaders GetCertificateFunc to enable hot reload
	tlsconf.GetCertificate = certReloader.GetCertificateFunc()

	// init server
	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsconf,
		Handler:   handler,
	}

	log.Println("serving: https://" + cfg.Domains[0])

	// lets go
	return s.ListenAndServeTLS("", "")
}

// Redirect a request to HTTPS and strips the www. subdomain
func Redirect(w http.ResponseWriter, req *http.Request) {

	target := "https://" + strings.TrimPrefix(req.Host, "www.") + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}

	fmt.Println("redirecting client to https: ", target, " ("+req.Host+")", "UserAgent:", req.UserAgent())
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

////////////////////
// Private
///////////////////

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

// runCommand executes the named command with the supplied arguments
// and fatals on error
func runCommand(cmd string, args ...string) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("[ERROR] failed to run command: ", cmd+strings.Join(args, " "))
		log.Fatal("[FATAL] simplecert: error: ", err, ", output: ", string(out))
	}
}
