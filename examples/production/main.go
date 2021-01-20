//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/foomo/simplecert"
	"github.com/foomo/tlsconfig"
)

type Handler struct{}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello from simplecert!"))
}

// This example demonstrates how spin up a custom HTTPS webserver for production deployment.
// It shows how to configure and start your service in a way that the certificate can be automatically renewed via the TLS challenge, before it expires.
// For this to succeed, we need to temporarily free port 443 (on which your service is running) and complete the challenge.
// Once the challenge has been completed the service will be restarted via the DidRenewCertificate hook.
// Requests to port 80 will always be redirected to the TLS secured version of your site.
func main() {

	var (
		// the structure that handles reloading the certificate
		certReloader *simplecert.CertReloader
		err          error
		numRenews    int
		ctx, cancel  = context.WithCancel(context.Background())

		// init strict tlsConfig (this will enforce the use of modern TLS configurations)
		// you could use a less strict configuration if you have a customer facing web application that has visitors with old browsers
		tlsConf = tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

		// a simple constructor for a http.Server with our Handler
		makeServer = func() *http.Server {
			return &http.Server{
				Addr:      ":443",
				Handler:   Handler{},
				TLSConfig: tlsConf,
			}
		}

		// init server
		srv = makeServer()

		// init simplecert configuration
		cfg = simplecert.Default
	)

	// configure
	cfg.Domains = []string{"yourdomain.com", "www.yourdomain.com"}
	cfg.CacheDir = "letsencrypt"
	cfg.SSLEmail = "you@emailprovider.com"

	// disable HTTP challenges - we will only use the TLS challenge for this example.
	cfg.HTTPAddress = ""

	// this function will be called just before certificate renewal starts and is used to gracefully stop the service
	// (we need to free port 443 in order to complete the TLS challenge)
	cfg.WillRenewCertificate = func() {
		// stop server
		cancel()
	}

	// this function will be called after the certificate has been renewed, and is used to restart your service.
	cfg.DidRenewCertificate = func() {

		numRenews++

		// restart server: both context and server instance need to be recreated!
		ctx, cancel = context.WithCancel(context.Background())
		srv = makeServer()

		// force reload the updated cert from disk
		certReloader.ReloadNow()

		go serve(ctx, srv)
	}

	log.Println("hello world")

	// init config
	certReloader, err = simplecert.Init(cfg, func() {
		os.Exit(0)
	})
	if err != nil {
		log.Fatal("simplecert init failed: ", err)
	}

	// redirect HTTP to HTTPS
	log.Println("starting HTTP Listener on Port 80")
	go http.ListenAndServe(":80", http.HandlerFunc(simplecert.Redirect))

	// enable hot reload
	tlsConf.GetCertificate = certReloader.GetCertificateFunc()

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
