Matrix Federation Tester
========================

Checks that federation is correctly configured on a matrix server.

Building
--------

The tester is written in [golang](https://golang.org/) and built using [gb](https://getgb.io).

```bash
go get github.com/constabulary/gb/...
gb build
```

Running
-------

```bash
BIND_ADDRESS=:8080 bin/matrix-federation-tester
```
