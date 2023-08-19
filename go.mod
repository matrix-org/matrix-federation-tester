module github.com/matrix-org/matrix-federation-tester

go 1.15

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/matrix-org/gomatrix v0.0.0-20220926102614-ceba4d9f7530 // indirect
	github.com/matrix-org/gomatrixserverlib v0.0.0-20230819231112-2812403ba8ee
	github.com/matrix-org/util v0.0.0-20221111132719-399730281e66 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/common v0.41.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/tidwall/gjson v1.16.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/crypto v0.12.0 // indirect
)

//replace github.com/matrix-org/gomatrixserverlib => ../gomatrixserverlib
