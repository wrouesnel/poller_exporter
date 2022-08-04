# Dockerfile for building the containerized poller_exporter
# golang:1.18 as of 2022-07-04
FROM golang@sha256:1bbb02af44e5324a6eabe502b6a928d368977225c0255bc9aca4a734145f86e1 AS build

MAINTAINER William Rouesnel <wrouesnel@wrouesnel.com>
EXPOSE 9115

ARG BUILDOS=linux
ARG BUILDARCH=amd64
ARG BUILDNAME=poller_exporter

COPY ./ /workdir/
WORKDIR /workdir

RUN GOOS=$BUILDOS \
    GOARCH=$BUILDARCH \
    CGO_ENABLED=0 \
    go build -a -o $BUILDNAME \
    -trimpath -ldflags '-buildid= -extldflags "-static"' \
    ./cmd/poller_exporter

FROM scratch

MAINTAINER Will Rouesnel <wrouesnel@wrouesnel.com>

ENV PATH=/bin
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs

ARG BUILDNAME=poller_exporter
ENV EXECUTABLE=$BUILDNAME
COPY --from=build /workdir/$BUILDNAME /bin/$BUILDNAME

ENTRYPOINT ["/bin/$EXECUTABLE"]
