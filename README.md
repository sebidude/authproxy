# authproxy

Simple TLS reverse proxy with TLS client auth and vhost support.

Example:
```
./authproxy example/authproxy.yaml
```

Use the client pkcs12 file ```example/certs/client-han.pfx``` for browser testing (password: han)

Server certs can be issued by a different CA than the client certs but only one ClientCA is supported.

