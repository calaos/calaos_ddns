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
in `/etc/profile.d/calaos.sh` for that. The calaos-container daemon drives the
same commands with `--json` for the web admin.

## Backend

All requests go to `https://ns1.calaos.fr/` (hard-coded constant, no override):

| Call | Used by |
| --- | --- |
| `POST api/register` (JSON: `mainzone`, `subzones`, `token`) | `register`, `change` |
| `GET api/update/<token>` | `update` |
| `DELETE api/delete/<token>` | `unregister`, `change` |
| `POST api/letsencrypt` / `DELETE api/letsencrypt` (TXT record for the ACME DNS-01 challenge) | certificate issuance and renewal |

Certificates come from Let's Encrypt production
(`https://acme-v02.api.letsencrypt.org/directory`) through the
[lego](https://github.com/xenolf/lego) library (v2.1.0), using a custom DNS-01
provider that relays the challenge to the Calaos DNS API. Keys are RSA 4096.

## Usage

```
calaos_ddns [--json] register DOMAIN [SUBDOMAIN...] [--email E] [--token-stdin]
calaos_ddns [--json] change NEWDOMAIN [--email E]
calaos_ddns [--json] update [-f]
calaos_ddns [--json] unregister [--local]
calaos_ddns [--json] reset
calaos_ddns [--json] status
calaos_ddns --version
```

`--json` is accepted before or after the command name.

- `register`: registers `DOMAIN.calaos.fr` and optional sub-domains
  (`SUB.DOMAIN.calaos.fr`), stores the returned token, requests a certificate
  covering all names, writes the PEM file and renders `haproxy.cfg`. It does not
  restart HAProxy.
  - `DOMAIN` must match `^[a-z0-9]{4,32}$`, a `SUBDOMAIN` `^[a-z0-9]{2,32}$`.
  - `DOMAIN=IP:PORT` points the default backend at another address instead of
    `127.0.0.1:5454` (calaos-server). Refused with `--json`.
  - `SUB=IP:PORT` adds a backend routed by TLS SNI to `SUB.DOMAIN.calaos.fr`.
    A sub-domain without `=IP:PORT` is registered in DNS but gets no HAProxy
    backend.
  - `--email`: the Let's Encrypt address, stored in `ddns_le_email`. Without it
    the stored one is used; if none is stored, the address is asked on stdin,
    except with `--json`, which never prompts.
  - `--token-stdin`: reads the token of an existing registration from the first
    line of stdin (never from the command line), for a reconnect.
  - Registering the same domain again with the stored token is a repair: when
    no `SUBDOMAIN` is given, the sub-domains known from the state file are sent
    again, so that none is dropped.
- `change`: registers `NEWDOMAIN` (with the current sub-domains) without a
  token, gets its certificate, stores the new token, deletes the old name with
  the old token, then writes the PEM file and renders `haproxy.cfg`. A failure
  before the token swap deletes the new name again and leaves the current
  registration, certificate and `haproxy.cfg` untouched.
- `update`: does nothing if no token is stored. Otherwise refreshes the IP,
  then renews the certificate if it expires within 30 days (`-f`,
  `--force-renew`: renew regardless). When no certificate is cached but the
  domain and an e-mail are known (restore on a new box), it requests one.
  After a new certificate it rewrites the PEM file and runs
  `/bin/systemctl restart haproxy.service`. It does not re-render
  `haproxy.cfg`.
- `unregister`: deletes the registration on the backend and the stored token.
  `--local` (and `reset`) only deletes the stored token, without calling the
  backend (for an expired or unknown token). The certificate cache and
  `haproxy.cfg` are left in place.
- `status`: prints the registration and certificate state. It takes no lock and
  makes no backend call; it asks the A record of the domain directly to
  `ns1.calaos.fr:53` (2 s timeout).

Every command except `status` holds `<cache>/calaos_ddns.lock`; a command
started while another one runs exits 5 at once (the systemd unit treats 5 as
success, so an overlap with the timer is not a failed run).

Output uses a spinner only when stdout is a terminal and `--json` is not given.

### JSON output and exit codes

With `--json`, stdout holds exactly one JSON object, printed at exit; human
messages go to stderr. Neither ever contains the token.

```
{"ok": true, ...}
{"ok": false, "error": {"code": "host_taken", "msg": "This name is already registered"}, ...}
```

| Exit | Meaning | `error.code` |
| --- | --- | --- |
| 0 | ok | |
| 1 | local or usage error | `invalid_name`, `wrong_token`, `unknown_token` (refused locally), `no_email`, `config_write`, `internal` |
| 2 | refused by the backend | `host_taken`, `wrong_token`, `unknown_token`, `invalid_name`, `internal` |
| 3 | backend unreachable (network, HTTP 5xx) | `backend_unreachable` |
| 4 | ACME or certificate failure | `acme_failed`, `dns_propagation` |
| 5 | another run holds the lock | `busy` |

`msg` is a fixed English text per code. Extra fields: `register` and `change`
give `domain`; `change` gives `old_deleted`; `update` gives `updated` and
`renewed`. `status --json` gives:

```
{"ok": true, "token_set": true, "domain": "maison", "subdomains": [{"name": "cam1", "ip": "192.168.1.20", "port": "8080"}],
 "email_set": true, "email": "r***@gmail.com", "registered_at": "2026-10-25T10:00:00Z",
 "last_update": {"at": "...", "ok": true, "code": "..."} | null,
 "last_cert": {"at": "...", "ok": true, "code": "...", "renewed": true} | null,
 "cert": {"issuer": "Let's Encrypt", "self_signed": false, "names": ["maison.calaos.fr"], "not_after": "..."} | null,
 "dns_ip": "203.0.113.7"}
```

`cert` describes `CALAOS_CERT_FILE`. `dns_ip` is empty when the domain is
unknown or `ns1.calaos.fr` does not answer.

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
  rewrites the options `ddns_token` and `ddns_le_email`, with calaos_server's
  protocol: `flock` on `local_config.xml.lock`, XML escaping, write to a
  temporary file renamed over the original (mode, owner and symlink kept). A
  file that does not parse is never rewritten. A missing file is treated as
  "not configured" on read; writes fail if it does not exist.
- Cache dir: `SSLUser.json` (ACME account), `CertResource.json`, `cert.pem`,
  `key.pem`, `cert_key.pem` (key + cert), `calaos_ddns.lock` (run lock),
  `state.json` (mode 0600: domain, sub-domains, `email_set`, `registered_at`,
  last update and last certificate results) and `calaos_ddns.log` (truncated
  at every locked run; lego logs go there too). Without `state.json` (older
  registration, restored backup), the domain and sub-domains are read from the
  served certificate and the proxied backends from `haproxy.cfg`.
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
go test -mod=vendor -race ./...
go vet -mod=vendor ./...
make clean
```

`make test` is intentionally a no-op ("test disabled"). The tests use a fake
Calaos DNS backend, a fake ACME issuer and a fake DNS server; they never reach
`ns1.calaos.fr` or Let's Encrypt. Because `go.mod` says `go 1.13`, the vendor
directory is not used implicitly by every command: pass `-mod=vendor`.

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
