Matrix Federation Tester
========================

Checks that federation is correctly configured on a matrix server.

Building
--------

The tester is written in [golang](https://golang.org/) 1.10+ and built using [gb](https://getgb.io).

```bash
go get github.com/constabulary/gb/...
gb build
```

Running
-------

```bash
BIND_ADDRESS=:8080 bin/matrix-federation-tester
```

Using
-----

The federation tester may be accessed using the following templated URL. Please replace `<server_name>` with your server name (eg: `matrix.org`).

```
https://matrix.org/federationtester/api/report?server_name=<server_name>
```
