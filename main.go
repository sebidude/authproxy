// Copyright 2017 Sebastian Stauch.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listenAddress  string
	targetAddress  string
	metricsAddress string
	caCertfile     string
	serverCert     string
	serverKey      string
	config         Configuration
)

type HostSwitch map[string]http.Handler

func (hs HostSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler := hs[r.Host]; handler != nil {
		handler.ServeHTTP(w, r)
	} else {
		// Handle host names for which no handler is registered
		http.Error(w, "Forbidden", 403) // Or Redirect?
	}
}

func main() {

	log.SetFlags(0)
	log.SetOutput(new(Logger))

	if len(os.Args) < 2 {
		fmt.Println("Missing parameter for configfile.")
		fmt.Printf("usage: %s <configfile>\n", os.Args[0])
		os.Exit(1)
	}

	log.Println("==== Reverse Auth Proxy ====")
	config, err := LoadConfig(os.Args[1])
	if err != nil {
		log.Panic(err)
	}
	listenAddress = config.ListenAddress
	metricsAddress = config.MetricsAddress
	caCertfile = config.CaFile

	log.Println("Configparams:")
	log.Printf(" listenAddress : %s", listenAddress)
	log.Printf(" metricsAddress: %s", metricsAddress)
	log.Printf(" caCert        : %s", caCertfile)
	// prepare the certpool

	gin.SetMode(gin.ReleaseMode)
	hostSwitch := make(HostSwitch)
	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = make([]tls.Certificate, len(config.VHosts))
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	caCert, err := ioutil.ReadFile(config.CaFile)
	if err != nil {
		log.Panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	log.Println(" Vhosts:")
	for k, host := range config.VHosts {
		log.Print(" - virtual host")
		log.Printf("   hostname     : %s", host.Hostname)
		log.Printf("   targetAddress: %s", host.TargetAddress)
		log.Printf("   serverCert   : %s", host.Tls.CertFile)
		log.Printf("   serverKey    : %s", host.Tls.KeyFile)

		tlsConfig.Certificates[k], err = tls.LoadX509KeyPair(host.Tls.CertFile, host.Tls.KeyFile)
		if err != nil {
			log.Panic(err)
		}

		proxy := gin.New()
		proxy.Use(GinLogger())
		proxy.Use(gin.Recovery())
		proxy.Use(ReverseProxy(host.TargetAddress))
		hostSwitch[host.Hostname] = proxy
	}
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	tlsserver := &http.Server{
		Addr:      listenAddress,
		Handler:   hostSwitch,
		TLSConfig: tlsConfig,
	}

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":8080", nil)

	log.Printf("Start reverse proxy on %s", listenAddress)
	tlslistener, err := tls.Listen("tcp", listenAddress, tlsConfig)
	if err != nil {
		log.Panic(err)
	}
	log.Fatal(tlsserver.Serve(tlslistener))
}

func ReverseProxy(target string) gin.HandlerFunc {
	url, err := url.Parse(target)
	if err != nil {
		log.Println(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	return func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}
