# Dockerfile for building the containerized poller_exporter
FROM alpine:latest
MAINTAINER William Rouesnel <w.rouesnel@gmail.com>
EXPOSE 9115

ENV GOPATH /go
ENV APPPATH $GOPATH/src/github.com/wrouesnel/poller_exporter
COPY . $APPPATH

RUN apk add --update -t build-deps go git mercurial libc-dev gcc libgcc \
    && cd $APPPATH && go get -d && go build -o /poller_exporter \
    && apk del --purge build-deps && rm -rf $GOPATH
    
ENTRYPOINT ["/poller_exporter"]
