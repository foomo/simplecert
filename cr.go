//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package simplecert

import (
	"github.com/xenolf/lego/certificate"
)

// CR represents an ACME Certificate Resource
// It can be persisted on the FileSystem with all fields
// which cannot be done with acme.CertificateResource
type CR struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"privateKey"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuerCertificate"`
	CSR               []byte `json:"csr"`
}

// get an ACME certificate resource from CR
func getACMECertResource(cr CR) *certificate.Resource {
	var cert = new(certificate.Resource)
	cert.Domain = cr.Domain
	cert.CertURL = cr.CertURL
	cert.CertStableURL = cr.CertStableURL
	cert.PrivateKey = cr.PrivateKey
	cert.Certificate = cr.Certificate
	cert.IssuerCertificate = cr.IssuerCertificate
	cert.CSR = cr.CSR
	return cert
}
