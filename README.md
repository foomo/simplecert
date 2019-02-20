# simplecert

         _                 _                    _
     ___(_)_ __ ___  _ __ | | ___  ___ ___ _ __| |_
    / __| | '_ ` _ \| '_ \| |/ _ \/ __/ _ \ '__| __|
    \__ \ | | | | | | |_) | |  __/ (_|  __/ |  | |_
    |___/_|_| |_| |_| .__/|_|\___|\___\___|_|   \__|
                    |_|

> Golang Library for automatic LetsEncrypt SSL Certificates

Obtains certificates automatically, and manages renewal and hot reload for your Golang application.
It uses the awesome [LEGO Library](https://github.com/xenolf/lego) to perform ACME challenges.
Lego is vendored with dep, in case of any breaking API changes.

Main goals:

- ease of use: simplicity and integration with go standard library
- transparency: products of intermediate steps are preserved, dedicated logfile for simplecert

UPDATE: The vendored lego version has been updated to v2.2.0 and now supports issuing wildcard certificates by using ACMEv2 challenges.

You need to supply the following data to simplecert: Domains, Contact Email and a Directory to store the certs in (CacheDir).
On startup, call the simplecert.Init() function and pass your config.
You will receive a certReloader instance, that has a GetCertificateFunc to allow hot reloading the cert upon renewal.
See Usage for a detailed example.

For more advanced usage, see the config section for all configuration options.

## Install

```shell
go get -u -v github.com/foomo/simplecert
```

## Usage

simplecert has a default configuration available: simplecert.Default

You will need to update the Domains, CacheDir and SSLEmail and you are ready to go.

```go
// do the cert magic
cfg := simplecert.Default
cfg.Domains = []string{"yourdomain.com", "www.yourdomain.com"}
cfg.CacheDir = "/etc/letsencrypt/live/yourdomain.com"
cfg.SSLEmail = "you@emailprovider.com"
cfg.DNSProvider = "cloudflare"
certReloader, err := simplecert.Init(cfg)
if err != nil {
    log.Fatal("simplecert init failed: ", err)
}

// redirect HTTP to HTTPS
// CAUTION: This has to be done AFTER simplecert setup
// Otherwise Port 80 will be blocked and cert registration fails!
log.Println("starting HTTP Listener on Port 80")
go http.ListenAndServe(":80", http.HandlerFunc(redirect))

// init strict tlsConfig with certReloader
// you could also use a default &tls.Config{}, but be warned this is highly insecure
tlsconf := tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)

// now set GetCertificate to the reloaders GetCertificateFunc to enable hot reload
tlsconf.GetCertificate = certReloader.GetCertificateFunc()

// init server
s := &http.Server{
    Addr:      ":443",
    TLSConfig: tlsconf,
}

// lets go
log.Fatal(s.ListenAndServeTLS("", ""))
```

## Configuration

You can pass a custom config to suit your needs.

Parameters are explained below.

```go
// Config allows configuration of simplecert
type Config struct {

    // renew the certificate X hours before it expires
    // LetsEncrypt Certs are valid for 90 Days
    RenewBefore int

    // Interval for checking if cert is closer to expiration than RenewBefore
    CheckInterval time.Duration

    // SSLEmail for contact
    SSLEmail string

    // ACME Directory URL. Can be set to https://acme-staging.api.letsencrypt.org/directory for testing
    DirectoryURL string

    // Endpoints for webroot challenge
    // CAUTION: challenge must be received on port 80 and 443
    // if you choose different ports here you must redirect the traffic
    HTTPAddress string
    TLSAddress  string

    // UNIX Permission for the CacheDir and all files inside
    CacheDirPerm os.FileMode

    // Domains for which to obtain the certificate
    Domains []string

    // Path of the CacheDir
    CacheDir string

    // DNSProvider name for DNS challenges (optional)
    // see: https://godoc.org/github.com/xenolf/lego/providers/dns
    DNSProvider string
}
```

## Debug

Simplecert writes all its logs to the *simplecert.log* file inside the configured cache directory.

## License

MIT