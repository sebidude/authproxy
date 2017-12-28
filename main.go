package main

import (
	"crypto/tls"
	"crypto/x509"
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

func main() {

	log.SetFlags(0)
	log.SetOutput(new(Logger))
	log.Println("Reverse Auth Proxy")

	if len(os.Args) < 2 {
		listenAddress = os.Getenv("AUTH_PROXY_LISTEN_ADDRESS")
		targetAddress = os.Getenv("AUTH_PROXY_TARGET_ADDRESS")
		metricsAddress = os.Getenv("AUTH_PROXY_METRICS_ADDRESS")
		caCertfile = os.Getenv("AUTH_PROXY_CACERT")
		serverCert = os.Getenv("AUTH_PROXY_CERT")
		serverKey = os.Getenv("AUTH_PROXY_KEY")
	} else {
		config, err := LoadConfig(os.Args[1])
		if err != nil {
			panic(err)
		}
		listenAddress = config.ListenAddress
		targetAddress = config.TargetAddress
		metricsAddress = config.MetricsAddress
		caCertfile = config.Tls.CaFile
		serverCert = config.Tls.CertFile
		serverKey = config.Tls.KeyFile
	}

	log.Println("Configparams:")
	log.Printf(" listenAddress : %s", listenAddress)
	log.Printf(" targetAddress : %s", targetAddress)
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
	proxy := gin.New()
	proxy.Use(GinLogger())
	proxy.Use(gin.Recovery())
	proxy.Use(ReverseProxy(targetAddress))

	adminGroup := proxy.Group("/admin")
	{
		adminGroup.GET("/healthz", func(c *gin.Context) {
			c.String(200, "healthy")
		})
	}

	tlsserver := &http.Server{
		Addr:    listenAddress,
		Handler: proxy,
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
