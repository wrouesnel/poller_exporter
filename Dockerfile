# Dockerfile for building the containerized poller_exporter
FROM golang:1.18 AS build
MAINTAINER William Rouesnel <wrouesnel@wrouesnel.com>
EXPOSE 9115

RUN go build -o poller_exporter ./

FROM scratch

ENV PATH=/bin
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs
COPY --from=build ./poller_exporter
    
ENTRYPOINT ["/poller_exporter"]
