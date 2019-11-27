package main

import (
	"flag"
	"fmt"
	"github.com/itdesigndev/cert"
	"os"
)

var c *cert.Config
var dir string

func init() {
	c = cert.New()
	flag.StringVar(&c.Host, "host", c.Host, "host for which certificate gets generated, can be a comma separated list")
	flag.StringVar(&c.ValidFrom, "validFrom", c.ValidFrom, "valid from date of certificate, format:01.02.2006")
	flag.DurationVar(&c.ValidFor, "validFor", c.ValidFor, "duration certificate is valid")
	flag.BoolVar(&c.IsCA, "isCa", c.IsCA, "is CA certificate")
	flag.IntVar(&c.RsaBits, "bits", c.RsaBits, "rsa bits")
	flag.StringVar(&c.EcdsaCurve, "ecdsaCurve", c.EcdsaCurve, "eliptic curve algorithm: supported values P224,P256,P384,P521 or empty to use rsa")
	flag.StringVar(&dir, "dir", "", "if specified generate cert.pem and key.pem in specified dir instead writing it to stdout")
	flag.Parse()
}

func main() {
	var err error
	if len(dir) > 0 {
		err = c.GenerateFiles(dir)
	} else {
		err = c.Generate(os.Stdout, os.Stdout)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
