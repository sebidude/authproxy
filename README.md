# authproxy

Simple TLS reverse proxy with TLS client auth and vhost support.

## Build
```
go get github.com/sebidude/authproxy
```
## Run
```
authproxy example/authproxy.yaml
```

Example config:
```
# The address on which the proxy accepts requests
listenAddress: localhost:8443

# prometheus metrics can be collected from this address 
# the path to the metrics is /metrics
metricsAddress: localhost:8080

# Specify the path to a CA cert for authenticating clients.
# comment this option to turn off x509 client auth
caFile: example/certs/ca.crt

# Configuration of the vhosts the proxy will handle
# List of vhosts holding
#  hostname: hostname[:port] which will trigger the proxy (SNI is used to determine the tls.Certificate)
#  targetAddress: the URI to which the requests will be forwarded.
#  log: set to true to log every request. if set to false no log messages will be written for the vhost
#  tls: the tls config
#    certFile: path to the file holding the certificate to be used with this vhost
#    keyFile: path to the file holding the key for the certFile 
#  addStaticRequestHeaders: list of additional (static) http headers passed to the vHost with each request
#    - name: name of the added header
#      value: value of the added header
#    - name: ...
#      value: ...
#  addStaticResponseHeaders: list of additional (static) http headers passed to the client with each response
#    - name: name of the added header
#      value: value of the added header
#    - name: ...
#      value: ...
vHosts:
  - hostname: hangar:8443
    targetAddress: http://localhost:9090
    log: true
    tls:
      certFile: example/certs/hangar.crt
      keyFile: example/certs/hangar.key
  - hostname: cantina:8443
    targetAddress: http://localhost:9100
    log: true
    tls:
      certFile: example/certs/cantina.crt
      keyFile: example/certs/cantina.key

```

Use the client pkcs12 file ```example/certs/client-han.pfx``` for browser testing (password: han)

Server certs can be issued by a different CA than the client certs but only one ClientCA is supported.

