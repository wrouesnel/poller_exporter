[![Build and Test](https://github.com/wrouesnel/poller_exporter/actions/workflows/integration.yml/badge.svg)](https://github.com/wrouesnel/poller_exporter/actions/workflows/integration.yml)
[![Release](https://github.com/wrouesnel/poller_exporter/actions/workflows/release.yml/badge.svg)](https://github.com/wrouesnel/poller_exporter/actions/workflows/release.yml)
[![Container Build](https://github.com/wrouesnel/poller_exporter/actions/workflows/container.yml/badge.svg)](https://github.com/wrouesnel/poller_exporter/actions/workflows/container.yml)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/poller_exporter/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/poller_exporter?branch=main)

# Prometheus poller_exporter
Blackbox service poller for Prometheus. It is intended
to provide a detailed metrics endpoint, and also a usable HTTP interface for
inspecting the state of a given hosts metrics.

# Getting Started

A prebuilt docker container is hosted on Github Packages:

```bash
docker run -it -p 9115:9115 -v /myconfig.yml:/poller_exporter.yml ghcr.io/wrouesnel/poller_exporter
```

Or you can build your own:
```bash
docker build -t poller_exporter .
docker run -p 9115:9115 -v /myconfig.yml:/poller_exporter.yml
```

Documentation on configuration options can be found in the complete parameters
example file [poller_exporter.complete.yml](./poller_exporter.complete.yml).

# Web UI

The web UI will provide basic information about the configured pollers - this
provides a degree of self-describing functionality.

For production deployments use a tagged release, or better, the full hash.
The docker containers default logging to JSON mode.

# Configuration
This tool is intended to be deployed on all servers in your environment, and its
configuration provised via a tool such as Ansible or a Kubernetes ConfigMap.

There are several types of checker, which internally simply represent logic
layers of each previous checker. Checkers are configured against hosts.

## Host Config

Hosts are DNS names (or IPs) which should be polled and have a series of 
`basic_checks`, `challenge_response_checks` and `http_checks`.

Each host by default is also ICMP ping checked, but this can be disabled in
cases where ICMP connectivity is not available or `poller_exporter` is running
without permissions to send ICMP.

### Basic Check

Basic checks simply check for open ports, and optionally validates TLS 
certificates.

### Challenge Response Checks

Challenge-Response checks send a configured byte-sequence to the TCP port and
check for a response - either a literal string or a byte-regex. This can be
used to check for example if OpenSSH is running by looking for the header.

* `response` looks for a literal response starting from the start of the line.
* `response_re` matches a regex anywhere along the line if not supplied with
anchor expressions. In general this is more useful.

It is not recommended to use this for HTTP, which is implemented as its own
checker due to occurrence and complexity.

### HTTP Checks

HTTP checker is an enhanced form of challenge-response checker which challenges
with an HTTP request. The given HTTP `verb` and `url` is used. I

**Important** `url` is *not* used to resolve the IP of the HTTP server - it is
solely used for the `Host:` header and query path.

The HTTP check can be configured to parse a range of `success_status` codes
which can be specified as a string-like `200-299,301,401`.

## Configuration Advice

The optimal configuration is a full mesh of related servers behind a network
segment - i.e. within a cluster of servers it is best for each server to poll
every other server to rapidly find connectivity issues.

# Hacking

To get started with the repository run `go run mage.go autogen` to configure
your repositories build hooks.

To build a binary for your current platform run `go run mage.go binary`