package main

import (
	"flag"
	"fmt"
	"github.com/itdesigndev/cert"
	"os"
)

var c *cert.Config

func init() {
	c = cert.New()
	flag.StringVar(&c.Host, "host", c.Host, "host for which certificate gets generated, can be a comma separated list")
	flag.StringVar(&c.ValidFrom, "validFrom", c.ValidFrom, "valid from date of certificate, format:01.02.2006")
	flag.DurationVar(&c.ValidFor, "validFor", c.ValidFor, "duration certificate is valid")
	flag.BoolVar(&c.IsCA, "isCa", c.IsCA, "is CA certificate")
	flag.IntVar(&c.RsaBits, "bits", c.RsaBits, "rsa bits")
	flag.StringVar(&c.EcdsaCurve, "ecdsaCurve", c.EcdsaCurve, "eliptic curve algorithm: supported values P224,P256,P384,P521 or empty to use rsa")
	flag.Parse()
}

func main() {
	if err := c.Generate(os.Stdout, os.Stdout); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
