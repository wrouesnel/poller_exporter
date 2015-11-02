# Ansible Deployment Roles

This role provides for deploying the poller_exporter as it is currently written.

It can be used by writing a pseudo-configuration file that specifies other
inventory items or literal hosts. This must be contained under a variable called
`linked_hosts`

To use it you need to compile the two copies of the poller_exporter and place
them in the files directory.

```bash
GOARCH=amd64 go build -o poller_exporter.x86_64
GOARCH=386 go build -o poller_exporter.i386
```

## Example
```yaml
linked_hosts:
- group: dns-servers
  basic_checks:
  - name: DNS
    proto: tcp
    port: 53
    timeout: 5s
- host: specific-host.example.com
  challenge_response_checks:
  - name: POP3
    proto: tcp
    port: 110
    response_re: "Dovecot ready."
    timeout: 10s
- literal:
  - www.google.com
  http_checks:
  - name: External Web
    proto: tcp
    port: 80
    timeout: 5s
    success_status: 100-102 200-226 300-308 401
```