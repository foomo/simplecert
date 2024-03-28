//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/foomo/tlsconfig"
)

var stopAfterNumRenews = 4

// testing with pebble ACME server:
//  1. go get github.com/letsencrypt/pebble and move into pebble project directory
//  2. add cert to trust store
//     $ sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain test/certs/pebble.minica.pem
//  3. start pebble ACME testing service, disable nonce rejection and challenge verification, as well as authz reuse:
//     $ PEBBLE_AUTHZREUSE=0 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json
//  4. point test domain to localhost in /etc/hosts
//     127.0.0.1	 mytestdomain.com
func TestRenewal(t *testing.T) {

	// pebble wont store any information on the file system
	// so we need to reset all state before contacting it initially
	// or we will be greeted with an error stating that the account https://0.0.0.0:14000/my-account/1 was not found
	_ = os.RemoveAll("simplecert")

	var (
		certReloader *CertReloader
		err          error
		numRenews    int
		ctx, cancel  = context.WithCancel(context.Background())

		// init strict tlsConfig
		tlsconf = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

		makeServer = func() *http.Server {
			return &http.Server{
				Addr:      ":5001",
				Handler:   nil, // http.DefaultServeMux
				TLSConfig: tlsconf,
			}
		}

		// init server
		srv = makeServer()

		// init simplecert configuration
		cfg = Default
	)

	// configure
	cfg.Domains = []string{"mytestdomain.com"}
	cfg.CacheDir = "simplecert"
	cfg.SSLEmail = "me@mail.com"
	cfg.DirectoryURL = "https://127.0.0.1:14000/dir"

	cfg.RenewBefore = int((90 * 24 * time.Hour) - 1*time.Minute) // renew if older than 1 minute after initial retrieval
	cfg.CheckInterval = 20 * time.Second                         // check every 20 seconds
	cfg.CacheDir = "simplecert"

	cfg.WillRenewCertificate = func() {
		// stop server
		cancel()
	}

	cfg.DidRenewCertificate = func() {

		numRenews++
		if numRenews == stopAfterNumRenews {
			os.Exit(0)
		}

		// restart server: both context and server instance need to be recreated!
		ctx, cancel = context.WithCancel(context.Background())
		srv = makeServer()

		// force reload the updated cert from disk
		certReloader.ReloadNow()

		go serve(ctx, srv)
	}

	// init config
	certReloader, err = Init(cfg, func() {
		os.Exit(0)
	})
	if err != nil {
		log.Fatal("simplecert init failed: ", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	// redirect HTTP to HTTPS
	log.Println("starting HTTP Listener on Port 80")
	go http.ListenAndServe(":80", http.HandlerFunc(Redirect))

	// enable hot reload
	tlsconf.GetCertificate = certReloader.GetCertificateFunc()

	// start serving
	log.Println("will serve at: https://" + cfg.Domains[0])
	serve(ctx, srv)

	fmt.Println("waiting forever")
	<-make(chan bool)
}

func serve(ctx context.Context, srv *http.Server) {

	// lets go
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %+s\n", err)
		}
	}()

	log.Printf("server started")
	<-ctx.Done()
	log.Printf("server stopped")

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	err := srv.Shutdown(ctxShutDown)
	if err == http.ErrServerClosed {
		log.Printf("server exited properly")
	} else if err != nil {
		log.Printf("server encountered an error on exit: %+s\n", err)
	}
}
