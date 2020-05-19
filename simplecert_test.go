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
	"testing"
	"net/http"
	"os"
	"time"

	"github.com/foomo/tlsconfig"
)

var stopAfterNumRenews = 2

func TestRenewal(t *testing.T) {

		var (
			numRenews int
			ctx, cancel = context.WithCancel(context.Background())

			// init strict tlsConfig
			tlsconf = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

			// init server
			srv = &http.Server{
				Addr:      ":5001",
				Handler:   nil, // http.DefaultServeMux
				TLSConfig: tlsconf,
			}

			// init simplecert configuration
			cfg = Default
		)

		// configure
		cfg.Domains = []string{"mydomain.com"}
		cfg.CacheDir = "simplecert"
		cfg.SSLEmail = "me@mail.com"
		cfg.DirectoryURL = "https://127.0.0.1:14000/dir"

		cfg.RenewBefore = int((90 * 24 * time.Hour) - 1 * time.Minute) // renew if older than 1 minute after initial retrieval
		cfg.CheckInterval = 20 * time.Second // check every 20 seconds
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

			// restart server
			go serveProd(ctx, srv)
		}

		// init config
		certReloader, err := Init(cfg, func() {
			os.Exit(0)
		})
		if err != nil {
			log.Fatal("simplecert init failed: ", err)
		}

		// redirect HTTP to HTTPS
		log.Println("starting HTTP Listener on Port 80")
		go http.ListenAndServe(":80", http.HandlerFunc(Redirect))

		// enable hot reload
		tlsconf.GetCertificate = certReloader.GetCertificateFunc()

		// start serving
		log.Println("will serve at: https://" + cfg.Domains[0])
		serveProd(ctx, srv)

		fmt.Println("waiting forever")
		<- make(chan bool)
}

func serveProd(ctx context.Context, srv *http.Server) {

	// lets go
	//cLog.Fatal(srv.ListenAndServeTLS("", ""))
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen:%+s\n", err)
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

	// block forever, to avoid having main quit after the first renewal
	// subsequent calls to serve should be done in a goroutine
	<-make(chan struct{})
}
