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
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "authproxy",
		Name:      "request_counter",
		Help:      "Counter for the requests handled by the proxy.",
	}, []string{"method", "code", "host", "target"})
)

type (
	HostSwitch   map[string]http.Handler
	ReverseProxy struct {
		Url                  *url.URL
		Host                 string
		Target               string
		AllowedOrganisations []string
		Headers              Headers
		Proxy                *httputil.ReverseProxy
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

func NewReverseProxy(host string, target string, headers Headers, orgs []string) *ReverseProxy {
	rp := &ReverseProxy{}
	rp.Host = host
	rp.Target = target
	rp.Headers = headers
	rp.AllowedOrganisations = orgs
	url, err := url.Parse(target)
	if err != nil {
		log.Println(err)
	}
	rp.Url = url
	rp.Proxy = httputil.NewSingleHostReverseProxy(url)
	rp.Proxy.Director = rp.director
	return rp
}

func (rp *ReverseProxy) director(req *http.Request) {
	req.Host = rp.Host
	req.URL.Scheme = rp.Url.Scheme
	req.URL.Host = rp.Url.Host
	req.Header.Set("Host", rp.Host)
	req.Header.Add("X-Real-IP", req.RemoteAddr)

	keys := reflect.ValueOf(rp.Headers).MapKeys()
	for _, v := range keys {
		key := v.String()
		req.Header.Add(key, rp.Headers[key])
	}
}

func (rp *ReverseProxy) HandleRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(rp.AllowedOrganisations) > 0 {
			allowed := false
			for _, org := range c.Request.TLS.PeerCertificates[0].Subject.Organization {
				for _, allowedOrg := range rp.AllowedOrganisations {
					if org == allowedOrg {
						allowed = true
					}
				}
			}
			if !allowed {
				c.AbortWithStatus(403)
				return
			}
		}
		rp.Proxy.ServeHTTP(c.Writer, c.Request)
		RequestCounter.WithLabelValues(
			c.Request.Method,
			strconv.Itoa(c.Writer.Status()),
			rp.Host,
			rp.Target).Inc()
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

	// use x509 client auth if cafile is set
	if len(config.CaFiles) > 0 {
		log.Print(" Auth:")
		caCertPool := x509.NewCertPool()
		for _, caCertFile := range config.CaFiles {
			log.Printf("  caCertFile    : %s", caCertFile)
			caCert, err := ioutil.ReadFile(caCertFile)
			if err != nil {
				log.Panic(err)
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}
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
		if len(host.Tls.AllowedOrgs) > 0 {
			log.Println("   allowedOrgs  :")
			for _, v := range host.Tls.AllowedOrgs {
				log.Printf("    - %s", v)
			}

		}

		if len(host.Headers) > 0 {
			log.Println("   headers      :")

			keys := reflect.ValueOf(host.Headers).MapKeys()
			for _, v := range keys {
				key := v.String()
				log.Printf("    %15s: %s", key, host.Headers[key])
			}
		}

		tlsConfig.Certificates[k], err = tls.LoadX509KeyPair(host.Tls.CertFile, host.Tls.KeyFile)
		if err != nil {
			log.Panic(err)
		}

		proxy := gin.New()
		if host.Log {
			proxy.Use(GinLogger())
		}

		reverseProxy := NewReverseProxy(host.Hostname, host.TargetAddress, host.Headers, host.Tls.AllowedOrgs)
		proxy.Use(gin.Recovery())
		proxy.Use(reverseProxy.HandleRequest())
		hostSwitch[host.Hostname] = proxy
	}
	tlsConfig.BuildNameToCertificate()

	tlsserver := &http.Server{
		Addr:      config.ListenAddress,
		Handler:   hostSwitch,
		TLSConfig: tlsConfig,
	}
	prometheus.MustRegister(RequestCounter)
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(config.MetricsAddress, nil)

	log.Printf("Start reverse proxy on %s", config.ListenAddress)
	tlslistener, err := tls.Listen("tcp", config.ListenAddress, tlsConfig)
	if err != nil {
		log.Panic(err)
	}
	log.Fatal(tlsserver.Serve(tlslistener))
}
