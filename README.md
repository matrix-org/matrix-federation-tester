Matrix Federation Tester
========================

Checks that federation is correctly configured on a matrix server.

Building
--------

The tester is written in [golang](https://golang.org/) 1.11+.

```bash
git clone https://github.com/matrix-org/matrix-federation-tester
cd matrix-federation-tester
go build
```

Running
-------

```bash
BIND_ADDRESS=:8080 ./matrix-federation-tester
```

Using
-----

The federation tester may be accessed using the following templated URL. Please replace `<server_name>` with your server name (eg: `matrix.org`).

```
https://matrix.org/federationtester/api/report?server_name=<server_name>
```
