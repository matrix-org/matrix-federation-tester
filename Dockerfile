FROM golang:1.12-alpine

COPY . /src
WORKDIR /src

RUN apk --update add git
RUN go build

FROM alpine

# We need this otherwise we don't have a good list of CAs
RUN apk --update add ca-certificates

WORKDIR /root/
COPY --from=0 /src/matrix-federation-tester .

CMD ["./matrix-federation-tester"]
