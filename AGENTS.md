# AGENTS.md

Go CLI (`calaos_ddns`): Calaos dynamic DNS client + Let's Encrypt certificate
and HAProxy config generator for Calaos-OS. See README.md for behaviour and
env vars.

## Commands

- Build: `make build` (outputs `bin/calaos_ddns`; no ldflags, so `--version`
  prints `BuildVersion` = "git" from `version.go`).
- Test: `go test -mod=vendor -race ./...`. Root package tests run the CLI in-process (`run()`) and as child processes of the test binary (`TestMain`), against fakes in `fakes_test.go` (backend, ACME, DNS); every path points at a temp dir. `make test` is a deliberate no-op.
- Verify: `go build -mod=vendor ./...`; `go vet -mod=vendor ./...` is clean. No linter or formatter config (staticcheck only reports old style issues).
- Dependencies are vendored (`vendor/`, committed). `go.mod` says `go 1.13`, so the vendor dir is not auto-selected: use `-mod=vendor` (without it Go downloads modules). After changing `go.mod` run `go mod vendor`.

## Layout

- `main.go`: CLI (mow.cli) with `register`, `change`, `unregister`, `update`, `reset`; `status.go`: `status`; `backend.go`: HTTP calls to the backend; `errors.go`: `--json` error codes and exit codes; `state.go`: `state.json`, served-certificate parsing, run lock.
- `calaos/`: read/write of `local_config.xml` (`ddns_token`, `ddns_le_email`).
- `cert/`: lego ACME client, cache handling, PEM output; `cert/calaosdns/` is the DNS-01 provider talking to `api/letsencrypt`.
- `haproxy/`: argument parsing/validation and rendering of `haproxy.template`.
- `vendor/github.com/calaos/calaos_dns/utils`: shared helpers (cache dir, log file) from another repo, vendored.
- `debian/`: package, systemd service and 2h timer. `.github/workflows/build_deb.yml`: CI.

## Gotchas

- Backend URL `https://ns1.calaos.fr/` is a variable in `backend.go` (`nsURL`) and in `cert/calaosdns/provider.go` (`BaseURL`); tests override both. The DNS-01 provider gets the token as a parameter (during `change` the new token is not stored yet).
- `utils.InitLogger()` truncates the log: it is called only once the run lock is held, and never by `status`.
- Never print or log the token: it is in the URL path of `api/update` and `api/delete`, so transport errors are stripped of their URL, and human output goes through `scrub`.
- `local_config.xml` writes go through `calaos.UpdateConfig` (flock on `local_config.xml.lock`, strict parse, atomic rename). `SetConfig` fails if the file is missing; `DeleteConfig` and `GetConfig` treat it as empty.
- The template hard-codes `/usr/local/etc/haproxy/server.pem`, independent of `CALAOS_CERT_FILE`.
- `register`/`change` render `haproxy.cfg` only when a certificate was obtained; `update` never re-renders it and only restarts HAProxy after a new certificate. `register` never restarts HAProxy (the daemon does).
- Hostname rules are duplicated: `haproxy/haconfig.go` (sub-domain min 2 chars) differs from `utils.IsValidSubHostname` (min 3).
- `debian/rules` hard-codes `VERSION = 1.0.0`; the real version comes from CI via `/build-deb.sh` (script lives in the build image, not this repo).
- Never run `register`/`update` against a real config in dev: they hit production `ns1.calaos.fr` and Let's Encrypt production (staging URL is a commented line in `cert/config.go`).

## Workflow and conventions

- A push to `main` triggers `build_deb.yml`: version bump, `.deb` build, git tag, GitHub prerelease, and a webhook to update the deb repository. Do not push to `main` casually. Manual dispatch creates a stable release.
- CI does not run tests or vet.
- Code is old-style Go (`ioutil`, `(err, value)` return order in `calaos.GetConfig`); keep to it. Commands return a `*cmdError`; `run()` turns it into the exit code and the `--json` object.
- License is GPL; keep `COPYING`.
