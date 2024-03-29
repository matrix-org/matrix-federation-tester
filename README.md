Matrix Federation Tester
========================

Checks that federation is correctly configured on a matrix server.

Building
--------

Requires [Go](https://golang.org/) 1.15.

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

The federation tester may be accessed using the following templated URLs. Please replace `<server_name>` with your server name (eg: `matrix.org`).

**Full JSON report**

```
https://matrix.org/federationtester/api/report?server_name=<server_name>
```

**Plain text response**

Returns `GOOD` if the federation is ok and `BAD` if it's not ok.

```
https://matrix.org/federationtester/api/federation-ok?server_name=<server_name>
```
