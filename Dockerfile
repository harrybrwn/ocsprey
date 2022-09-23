FROM golang:1.19.1-alpine3.16 as builder
WORKDIR /opt/ocsprey
COPY go.mod go.sum /opt/ocsprey/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -o ./bin/ocsprey

FROM alpine:3.16
COPY --from=builder /opt/ocsprey/bin/ocsprey /usr/local/bin/
ENTRYPOINT [ "ocsprey" ]