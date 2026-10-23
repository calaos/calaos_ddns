# calaos_ddns

Dynamic DNS client for Calaos. It registers a `*.calaos.fr` name for a home,
keeps its IP address up to date, obtains and renews a Let's Encrypt
certificate, and generates the HAProxy configuration that terminates HTTPS in
front of `calaos-server`.

## Role in Calaos-OS

The Debian package `calaos-ddns` installs the `calaos_ddns` binary, an HAProxy
template and a systemd timer. The timer runs `calaos_ddns update` one minute
after boot and then every 2 hours; the paths in the shipped systemd unit point
under `/mnt/calaos`. `register` and `unregister` are run by hand from a shell on
the box: the `calaos-container` package exports the same environment variables
in `/etc/profile.d/calaos.sh` for that.

## Backend

All requests go to `https://ns1.calaos.fr/` (hard-coded constant, no override):

| Call | Used by |
| --- | --- |
| `POST api/register` (JSON: `mainzone`, `subzones`, `token`) | `register` |
| `GET api/update/<token>` | `update` |
| `DELETE api/delete/<token>` | `unregister` |
| `POST api/letsencrypt` / `DELETE api/letsencrypt` (TXT record for the ACME DNS-01 challenge) | certificate issuance and renewal |

Certificates come from Let's Encrypt production
(`https://acme-v02.api.letsencrypt.org/directory`) through the
[lego](https://github.com/xenolf/lego) library (v2.1.0), using a custom DNS-01
provider that relays the challenge to the Calaos DNS API. Keys are RSA 4096.

## Usage

```
calaos_ddns register DOMAIN [SUBDOMAIN...]
calaos_ddns update [-f]
calaos_ddns unregister
calaos_ddns reset
calaos_ddns --version
```

- `register`: registers `DOMAIN.calaos.fr` and optional sub-domains
  (`SUB.DOMAIN.calaos.fr`), stores the returned token, asks for a Let's
  Encrypt e-mail address on stdin if none is stored, requests a certificate
  covering all names, writes the PEM file and renders `haproxy.cfg`.
  - `DOMAIN` must match `^[a-z0-9]{4,32}$`, a `SUBDOMAIN` `^[a-z0-9]{2,32}$`.
  - `DOMAIN=IP:PORT` points the default backend at another address instead of
    `127.0.0.1:5454` (calaos-server).
  - `SUB=IP:PORT` adds a backend routed by TLS SNI to `SUB.DOMAIN.calaos.fr`.
    A sub-domain without `=IP:PORT` is registered in DNS but gets no HAProxy
    backend.
- `update`: does nothing if no token is stored. Otherwise refreshes the IP,
  then renews the certificate if it expires within 30 days (`-f`,
  `--force-renew`: renew regardless). After a renewal it rewrites the PEM file
  and runs `/bin/systemctl restart haproxy.service`. It does not re-render
  `haproxy.cfg`.
- `unregister`: deletes the registration on the backend and the stored token.
  The certificate cache and `haproxy.cfg` are left in place.
- `reset`: only deletes the stored token locally (for an expired token); no
  call to the backend.

Output uses a spinner only when stdout is a terminal.

## Configuration

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CALAOS_CONFIG` | first of `~/.config/calaos`, `/etc/calaos` that contains `local_config.xml` | Directory of `local_config.xml` |
| `CALAOS_CERT_FILE` | `/etc/ssl/haproxy/server.pem` | Output file: private key followed by certificate chain, mode 0600 |
| `CALAOS_HAPROXY_TEMPLATE_PATH` | `/etc/haproxy` | Directory containing `haproxy.template` |
| `CALAOS_HAPROXY_PATH` | `/etc/haproxy` | Directory where `haproxy.cfg` is written |
| `CALAOSDNS_CACHE_DIR` | `~/.cache/calaos/ddns` | Cache dir (mode 0700): ACME account, certificate, log |
| `CALAOSDNS_PROPAGATION_TIMEOUT` | 120 (seconds) | DNS-01 propagation timeout |
| `CALAOSDNS_POLLING_INTERVAL` | 2 (seconds) | DNS-01 polling interval |

The shipped `calaos-ddns.service` sets `HOME=/home/root`,
`CALAOS_HAPROXY_PATH=/mnt/calaos/haproxy`,
`CALAOS_CERT_FILE=/mnt/calaos/haproxy/server.pem`,
`CALAOS_CONFIG=/mnt/calaos/config`,
`CALAOS_HAPROXY_TEMPLATE_PATH=/usr/share/calaos-ddns` and
`CALAOSDNS_CACHE_DIR=/mnt/calaos/calaos-ddns`.

## Files read and written

- `local_config.xml` (in the config dir, created by calaos-server): reads and
  rewrites the options `ddns_token` and `ddns_le_email`. A missing file is
  treated as "not configured" on read; writes fail if it does not exist.
- Cache dir: `SSLUser.json` (ACME account), `CertResource.json`, `cert.pem`,
  `key.pem`, `cert_key.pem` (key + cert), and `calaos_ddns.log` (truncated at
  every run; lego logs go there too).
- `CALAOS_CERT_FILE`: copy of `cert_key.pem`.
- `haproxy.cfg`: rendered from `haproxy.template` (installed to
  `/usr/share/calaos-ddns`). It listens on :80 (default backend) and :443
  (TLS, SNI routing). The template hard-codes the certificate path
  `/usr/local/etc/haproxy/server.pem`, which is not derived from
  `CALAOS_CERT_FILE`; the file must be visible at that path in the HAProxy
  environment.

## Build and test

Requires Go; dependencies are vendored (`go.mod` declares `go 1.13`).

```
make build      # bin/calaos_ddns
make coverage   # go test -cover ./...
go test -mod=vendor -vet=off ./...   # unit tests (calaos package only)
make clean
```

`make test` is intentionally a no-op ("test disabled"). `go vet` currently reports
issues in `main.go` (e.g. `fmt.Errorf` without format verbs), which makes a plain
`go test ./...` fail to build the root package; hence `-vet=off`. Because
`go.mod` says `go 1.13`, the vendor directory is not used implicitly by every
command: pass `-mod=vendor`.

## Packaging and release

- `debian/` builds the `calaos-ddns` package (debhelper 11, `golang`), which
  installs `bin/calaos_ddns` to `/usr/bin` and the template to
  `/usr/share/calaos-ddns`, plus the service and timer.
- `.github/workflows/build_deb.yml` runs on every push to `main` and on manual
  dispatch (`major`/`minor`/`patch`). It bumps the version with
  `calaos/action-bump-version`, builds the `.deb` in
  `ghcr.io/calaos/debian_deb_build_base` via `/build-deb.sh`, uploads it as an
  artifact, creates a git tag and a GitHub release, and calls a webhook to
  refresh the Calaos deb repository. A push to `main` produces a prerelease
  (kept out of the stable channel); a manual dispatch produces a stable release.

## License

GNU GPL (text in `COPYING`).
