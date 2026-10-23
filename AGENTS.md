# AGENTS.md

Go CLI (`calaos_ddns`): Calaos dynamic DNS client + Let's Encrypt certificate
and HAProxy config generator for Calaos-OS. See README.md for behaviour and
env vars.

## Commands

- Build: `make build` (outputs `bin/calaos_ddns`; no ldflags, so `--version`
  prints `BuildVersion` = "git" from `version.go`).
- Test: `CALAOSDNS_CACHE_DIR=$(mktemp -d) go test -mod=vendor -vet=off ./...` (plain `go test ./...` fails: vet errors in `main.go` break the root package build). `make test` is a deliberate no-op; `make coverage` runs tests without those flags. Only `calaos/config_test.go` exists.
- Verify: `go build -mod=vendor ./...`; `go vet -mod=vendor ./...` currently reports 13 pre-existing issues (Errorf without verbs, unreachable code in `cert/calaosdns/provider.go`, malformed tag `json:domains` in `cert/utils.go`). No linter or formatter config.
- Dependencies are vendored (`vendor/`, committed). `go.mod` says `go 1.13`, so the vendor dir is not auto-selected: use `-mod=vendor` (without it Go downloads modules). After changing `go.mod` run `go mod vendor`.

## Layout

- `main.go`: CLI (mow.cli) with `register`, `unregister`, `update`, `reset`; HTTP calls to the backend.
- `calaos/`: read/write of `local_config.xml` (`ddns_token`, `ddns_le_email`).
- `cert/`: lego ACME client, cache handling, PEM output; `cert/calaosdns/` is the DNS-01 provider talking to `api/letsencrypt`.
- `haproxy/`: argument parsing/validation and rendering of `haproxy.template`.
- `vendor/github.com/calaos/calaos_dns/utils`: shared helpers (cache dir, log file) from another repo, vendored.
- `debian/`: package, systemd service and 2h timer. `.github/workflows/build_deb.yml`: CI.

## Gotchas

- Backend URL `https://ns1.calaos.fr/` is duplicated in `main.go` and `cert/calaosdns/provider.go`, as are `doRequest` and the `ddns_token` key.
- Importing `calaos` calls `utils.InitLogger()` in `init()`, which opens the log in the cache dir (created if missing) and truncates it; unit tests therefore touch `CALAOSDNS_CACHE_DIR` or `~/.cache/calaos/ddns`. Set `CALAOSDNS_CACHE_DIR` to a temp dir when testing.
- `SetConfig`/`DeleteConfig` fail if `local_config.xml` is missing; `GetConfig` treats it as empty.
- The template hard-codes `/usr/local/etc/haproxy/server.pem`, independent of `CALAOS_CERT_FILE`.
- `register` renders `haproxy.cfg` only when a certificate was obtained; `update` never re-renders it and only restarts HAProxy after a renewal.
- Hostname rules are duplicated: `haproxy/haconfig.go` (sub-domain min 2 chars) differs from `utils.IsValidSubHostname` (min 3).
- `debian/rules` hard-codes `VERSION = 1.0.0`; the real version comes from CI via `/build-deb.sh` (script lives in the build image, not this repo).
- Never run `register`/`update` against a real config in dev: they hit production `ns1.calaos.fr` and Let's Encrypt production (staging URL is a commented line in `cert/config.go`).

## Workflow and conventions

- A push to `main` triggers `build_deb.yml`: version bump, `.deb` build, git tag, GitHub prerelease, and a webhook to update the deb repository. Do not push to `main` casually. Manual dispatch creates a stable release.
- CI does not run tests or vet.
- Code is old-style Go: `ioutil`, `(err, value)` return order in `calaos.GetConfig`, errors printed via `exit(err, code)`; keep to the existing style in touched files. Errors from `fmt.Errorf` in `main.go` sometimes lack a `%v` verb (vet warnings).
- License is GPL; keep `COPYING`.
