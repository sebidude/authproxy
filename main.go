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

	log.Println("Reverse Auth Proxy")
	config, err := LoadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}
	listenAddress = config.ListenAddress
	metricsAddress = config.MetricsAddress
	caCertfile = config.Tls.CaFile
	serverCert = config.Tls.CertFile
	serverKey = config.Tls.KeyFile

	log.Println("Configparams:")
	log.Printf(" listenAddress : %s", listenAddress)
	log.Printf(" metricsAddress: %s", metricsAddress)
	log.Printf(" caCert        : %s", caCertfile)
	log.Printf(" serverCert    : %s", serverCert)
	log.Printf(" serverKey     : %s", serverKey)

	// prepare the certpool
	caCert, err := ioutil.ReadFile(caCertfile)
	if err != nil {
		log.Panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	gin.SetMode(gin.ReleaseMode)
	hostSwitch := make(HostSwitch)

	log.Println(" Vhosts:")
	for _, host := range config.VHosts {
		log.Printf(" %-20s -> %s", host.Hostname, host.TargetAddress)
		proxy := gin.New()
		proxy.Use(GinLogger())
		proxy.Use(gin.Recovery())
		proxy.Use(ReverseProxy(host.TargetAddress))
		hostSwitch[host.Hostname] = proxy
	}

	tlsserver := &http.Server{
		Addr:    listenAddress,
		Handler: hostSwitch,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		},
	}

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":8080", nil)

	log.Printf("Start reverse proxy on %s", listenAddress)
	err = tlsserver.ListenAndServeTLS(
		serverCert,
		serverKey)
	if err != nil {
		log.Fatal(err)
	}
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
