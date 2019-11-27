//
// from: https://golang.org/src/crypto/tls/generate_cert.go
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Host       string
	ValidFrom  string
	ValidFor   time.Duration
	IsCA       bool
	RsaBits    int
	EcdsaCurve string
	Subject    pkix.Name
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (block *pem.Block, err error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err == nil {
			block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
		}
	}
	return
}

func New() *Config {
	host, _ := os.Hostname()
	return &Config{
		Host:     host,
		ValidFor: 20 * 365 * 24 * time.Hour, // 20 years
		RsaBits:  2048,
		Subject: pkix.Name{
			Organization: []string{"Acme"},
		},
	}
}

// Generate generates certificate and key with specified config
func (c *Config) Generate(cert io.Writer, key io.Writer) (err error) {

	var priv interface{}

	switch c.EcdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, c.RsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("unrecognized elliptic curve: %q", c.EcdsaCurve)
	}

	if err != nil {
		return
	}

	var notBefore time.Time
	if len(c.ValidFrom) == 0 {
		notBefore = time.Now()
	} else {
		if notBefore, err = time.Parse("02.01.2006", c.ValidFrom); err != nil {
			return
		}
	}

	notAfter := notBefore.Add(c.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               c.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(c.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if c.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return
	}

	// generate public key
	if err = pem.Encode(key, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return
	}

	// generate private key
	block, err := pemBlockForKey(priv)
	if err != nil {
		return
	}

	if err = pem.Encode(cert, block); err != nil {
		return
	}

	return
}

// GenerateFiles generate certificate and key and writes it to specified dir in files cert.pem and key.pem
func (c *Config) GenerateFiles(dir string) (err error) {
	certFile := dir + string(os.PathSeparator) + "cert.pem"
	keyFile := dir + string(os.PathSeparator) + "key.pem"
	cert, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	defer cert.Close()
	key, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	defer key.Close()
	err = c.Generate(cert, key)
	return
}
