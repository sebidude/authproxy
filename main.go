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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type (
	HostSwitch   map[string]http.Handler
	ReverseProxy struct {
		RequestCounter *prometheus.CounterVec
	}
)

func (hs HostSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler := hs[r.Host]; handler != nil {
		handler.ServeHTTP(w, r)
	} else {
		// Handle host names for which no handler is registered
		http.Error(w, "Forbidden", 403) // Or Redirect?
	}
}

func NewReverseProxy() *ReverseProxy {
	rp := &ReverseProxy{}
	rp.RequestCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "proxy",
		Name:      "request_counter",
		Help:      "Counter for the requests handled by the proxy.",
	}, []string{"method", "code", "host", "target"})
	return rp
}

func (rp *ReverseProxy) HandleRequest(host, target string) gin.HandlerFunc {
	url, err := url.Parse(target)
	if err != nil {
		log.Println(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	return func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
		rp.RequestCounter.WithLabelValues(
			c.Request.Method,
			strconv.Itoa(c.Writer.Status()),
			host,
			url.Host).Inc()
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

	log.Println("Configparams:")
	log.Printf(" listenAddress : %s", config.ListenAddress)
	log.Printf(" metricsAddress: %s", config.MetricsAddress)

	gin.SetMode(gin.ReleaseMode)
	hostSwitch := make(HostSwitch)
	tlsConfig := &tls.Config{}
	reverseProxy := NewReverseProxy()

	// use x509 client auth if cafile is set
	if len(config.CaFile) > 0 {
		log.Print(" Auth:")
		log.Printf("  caCert        : %s", config.CaFile)
		caCert, err := ioutil.ReadFile(config.CaFile)
		if err != nil {
			log.Panic(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	tlsConfig.Certificates = make([]tls.Certificate, len(config.VHosts))
	log.Println(" Vhosts:")
	for k, host := range config.VHosts {
		log.Print(" - virtual host")
		log.Printf("   hostname     : %s", host.Hostname)
		log.Printf("   targetAddress: %s", host.TargetAddress)
		log.Printf("   log          : %t", host.Log)
		log.Printf("   serverCert   : %s", host.Tls.CertFile)
		log.Printf("   serverKey    : %s", host.Tls.KeyFile)

		tlsConfig.Certificates[k], err = tls.LoadX509KeyPair(host.Tls.CertFile, host.Tls.KeyFile)
		if err != nil {
			log.Panic(err)
		}

		proxy := gin.New()
		if host.Log {
			proxy.Use(GinLogger())
		}
		proxy.Use(gin.Recovery())
		proxy.Use(reverseProxy.HandleRequest(host.Hostname, host.TargetAddress))
		hostSwitch[host.Hostname] = proxy
	}
	tlsConfig.BuildNameToCertificate()

	tlsserver := &http.Server{
		Addr:      config.ListenAddress,
		Handler:   hostSwitch,
		TLSConfig: tlsConfig,
	}
	prometheus.MustRegister(reverseProxy.RequestCounter)
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(config.MetricsAddress, nil)

	log.Printf("Start reverse proxy on %s", config.ListenAddress)
	tlslistener, err := tls.Listen("tcp", config.ListenAddress, tlsConfig)
	if err != nil {
		log.Panic(err)
	}
	log.Fatal(tlsserver.Serve(tlslistener))
}
