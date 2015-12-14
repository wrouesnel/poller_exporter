[![Build Status](https://travis-ci.org/wrouesnel/poller_exporter.svg)](https://travis-ci.org/wrouesnel/poller_exporter)
# Prometheus poller_exporter
This is my own spin on a blackbox service poller for Prometheus. It is intended
to provide a detailed metrics endpoint, and also a usable HTTP interface for
inspecting the state of a given hosts metrics.

# Deployment
This tool is intended to be deployed on all servers in your environment, and its
configuration provised via a tool such as Ansible.

Each server then expresses the network connections it has remotely, and provides
a direct interface to view their status, providing self-describing infrastructure.

# Configuration
`response` looks for a literal response starting from the start of the line.

`response_re` matches a regex anywhere along the line if not supplied with
anchor expressions. In general this is more useful.

Both forms work on the byte-stream returned by the service - no utf-8 conversion
is done for obvious reasons.

# Deploying via Docker
Docker deployment can be done with the following:
```
$ docker build -t poller_exporter .
$ docker run -p 9115:9115 -v /myconfig.yml:/poller_exporter.yml
```
