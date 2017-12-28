# authproxy

Simple TLS reverse proxy with TLS client auth and vhost support.

Example:
```
./authproxy example/authproxy.yaml
```
Use the client pkcs12 file ```example/certs/client-han.pfx``` for browser testing (password: han)

Server cert can be issued by a different CA than the client cert.

It does not support different server certificates for different vhosts, so you have to use SubAltNames.
