#! /bin/bash

# Enable TLSv1.3 on Go 1.12
export GODEBUG=tls13=1
export BIND_ADDRESS=:8700
exec $HOME/matrix-federation-tester/matrix-federation-tester
