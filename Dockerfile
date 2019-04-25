FROM golang:1.12-alpine

COPY . /src
WORKDIR /src

RUN apk --update add git
RUN go build

FROM alpine

WORKDIR /root/
COPY --from=0 /src/matrix-federation-tester .

CMD ["./matrix-federation-tester"]
