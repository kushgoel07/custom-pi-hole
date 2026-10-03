# Custom Pi DNS sinkhole

A Go DNS forwarder for the original Raspberry Pi Zero W (2017). It answers
blocked domain queries with NXDOMAIN and forwards other queries to an upstream
DNS server. Both UDP and TCP are supported, including TCP retry when an upstream
UDP response is truncated.

The Pi joins your home network over Wi-Fi. Configure your computer's DNS server,
or your router's DHCP DNS setting, to point to the Pi's reserved LAN IP address.
It does not need to act as an Ethernet bridge or carry all network traffic.

## Development

### Code layout

- `cmd/sinkhole/main.go`: application entry point and signal handling.
- `cmd/sinkhole/config.go`: command-line settings, validation, and list loading.
- `cmd/sinkhole/server.go`: UDP/TCP startup and shutdown.
- `internal/sinkhole/handler.go`: request validation, blocking, and forwarding.
- `internal/sinkhole/domains.go`: list parsing and domain matching.

Install Go 1.27.1 or newer, then run from the repository root:

```sh
go test ./...
go run ./cmd/sinkhole
```

The default listens on `127.0.0.1:5353` and forwards to `1.1.1.1:53`.
Query it from a machine with `dig` installed:

```sh
dig @127.0.0.1 -p 5353 doubleclick.net A   # expected: NXDOMAIN
dig @127.0.0.1 -p 5353 example.org A      # expected: upstream answer
dig +tcp @127.0.0.1 -p 5353 example.org A
```

On Windows, after binding to port 53 instead of 5353, you can use
`nslookup doubleclick.net 127.0.0.1`. System DNS clients expect port 53.

## Blocklists and options

`blocklist.txt` contains **two starter domains**, not a comprehensive ad list.
Add domains yourself or supply a trusted local hosts-format list:

```text
# Domains match themselves and their subdomains, ignoring case.
ads.example
0.0.0.0 tracker.example another-tracker.example # hosts-format entries
```

Blank lines and `#` comments are ignored. Localhost entries are skipped.
Malformed entries stop startup with a line number. URL lists, wildcard syntax,
and browser filter syntax are not supported. International domains must use
their ASCII/punycode form.

An optional allowlist uses the same format. An allowed domain and its subdomains
override a blocked parent domain. Files are loaded at startup; restart after
editing them.

```sh
go run ./cmd/sinkhole -listen 127.0.0.1:5353 -upstream 1.1.1.1:53 -blocklist blocklist.txt -allowlist allowlist.txt -timeout 3s -max-inflight 64
```

`-clients` is a comma-separated list of CIDRs that may use the resolver. By
default, only loopback clients are accepted. Set it to your home subnet when
binding a LAN address. The upstream must be a literal IP with a port;
bracket IPv6 addresses, for example `[2606:4700:4700::1111]:53`.

The server returns SERVFAIL if upstream lookup fails or all query slots are busy.
It refuses zone transfers, non-IN questions, and clients outside the configured
networks. It accepts one question per request. Blocked replies have a 60-second
negative cache lifetime.

## Build for the Pi Zero W

The original Zero W requires a 32-bit ARMv6 binary. See the official
[Pi hardware table](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html)
and [Go ARM build documentation](https://go.dev/wiki/GoArm).
Cross-compile on your development computer:

PowerShell:

```powershell
$env:GOOS = 'linux'
$env:GOARCH = 'arm'
$env:GOARM = '6'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags='-s -w' -o dist/sinkhole ./cmd/sinkhole
Remove-Item Env:GOOS, Env:GOARCH, Env:GOARM, Env:CGO_ENABLED
```

Linux/macOS:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -ldflags='-s -w' -o dist/sinkhole ./cmd/sinkhole
```

## Install on the Pi

These instructions assume 32-bit Raspberry Pi OS with SSH and systemd.
Reserve an IP for the Pi in your router. Replace `192.168.1.10` and
`192.168.1.0/24` with the Pi's IP and your LAN subnet.

Copy the binary, blocklist, and service file to the Pi (replace `pi` with your
SSH username):

```sh
scp dist/sinkhole blocklist.txt deploy/sinkhole.service pi@192.168.1.10:~
```

On the Pi:

```sh
sudo install -d -m 755 /opt/sinkhole
sudo install -m 755 ~/sinkhole /opt/sinkhole/sinkhole
sudo install -m 644 ~/blocklist.txt /opt/sinkhole/blocklist.txt
# Edit ExecStart to use your actual Pi IP and home subnet before installing.
nano ~/sinkhole.service
sudo install -m 644 ~/sinkhole.service /etc/systemd/system/sinkhole.service
sudo systemctl daemon-reload
sudo systemctl enable --now sinkhole
sudo systemctl status sinkhole
journalctl -u sinkhole -n 50 --no-pager
```

The service runs with a temporary unprivileged user and the capability needed
to bind port 53. Ensure port 53 is available on the configured IP and any
firewall allows UDP and TCP port 53 from your LAN. Do not forward DNS ports from
your router's public interface. Do not set the upstream to this sinkhole, or to
a router that forwards DNS back to it.

First set one computer to use the Pi as its DNS server and verify blocked and
allowed queries. Then set your router's DHCP DNS option to the Pi and renew
client leases. A secondary public DNS server can bypass blocking. Clients using
IPv6 DNS or browser/app encrypted DNS can also bypass the Pi unless those
settings use the intended resolver. Restore the previous DNS settings to roll
back; clients lose name resolution if their only DNS server is an offline Pi.

## Current scope

Filtering applies to the requested domain, including A, AAAA, and HTTPS queries.
It does not inspect returned CNAME chains. DNS cannot remove ads served from the
same domain as wanted content. This version has no local answer cache, automatic
list downloads, dashboard, per-query logging, DHCP server, or encrypted upstream
DNS. It logs startup and errors without retaining client browsing history.

The DNS protocol implementation uses [miekg/dns](https://github.com/miekg/dns).
