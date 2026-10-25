package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calaos/calaos_ddns/cert/calaosdns"
)

// A child process runs the real main path (os.Exit, flock between processes)
// against the fake backend whose URL is given in the environment.
func TestMain(m *testing.M) {
	if os.Getenv("CALAOS_DDNS_TEST_CHILD") == "1" {
		nsURL = os.Getenv("CALAOS_DDNS_TEST_NS")
		calaosdns.BaseURL = nsURL
		nsDNSAddr = "127.0.0.1:9"
		acme := &fakeACME{}
		issueCert = acme.generate
		renewCert = acme.renew
		restartHaproxy = func() error { return nil }
		os.Exit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestRegisterJSON(t *testing.T) {
	e := newEnv(t)

	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s %s", r.exit, r.stdout, r.stderr)
	}
	h := e.backend.host("maison")
	if h == nil {
		t.Fatal("not registered on the backend")
	}
	if e.backend.body(0).Token != "" {
		t.Fatal("a first register must not send a token")
	}
	if got := e.config(KEY_TOKEN); got != h.token {
		t.Fatalf("token stored %q, want %q", got, h.token)
	}
	if got := e.config(KEY_LE_EMAIL); got != "raoul@example.com" {
		t.Fatalf("email %q", got)
	}
	if got := e.config("smtp_password"); got != smtpPassword {
		t.Fatalf("smtp_password altered: %q", got)
	}

	call := e.acme.last()
	if call.token != h.token || call.email != "raoul@example.com" || strings.Join(call.domains, ",") != "maison.calaos.fr" {
		t.Fatalf("ACME call %+v", call)
	}

	st := e.state()
	if st.Domain != "maison" || !st.EmailSet || st.RegisteredAt == "" || st.LastCert == nil || !st.LastCert.OK || !st.LastCert.Renewed {
		t.Fatalf("state %+v", st)
	}
	fi, _ := os.Stat(e.path("cache", "state.json"))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("state.json mode %v", fi.Mode())
	}
	if _, err := os.Stat(e.path("haproxy", "server.pem")); err != nil {
		t.Fatal("PEM not written")
	}
	cfg, err := os.ReadFile(e.path("haproxy", "haproxy.cfg"))
	if err != nil || !strings.Contains(string(cfg), "server calaos-server 127.0.0.1:5454") {
		t.Fatalf("haproxy.cfg: %v %s", err, cfg)
	}
	if e.restarts != 0 {
		t.Fatal("register must not restart haproxy")
	}
}

func TestRegisterOptionsBeforeDomain(t *testing.T) {
	e := newEnv(t)
	r := e.run("", "register", "--json", "--email", "raoul@example.com", "maison")
	if r.exit != 0 || e.backend.host("maison") == nil {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
}

func TestRegisterInteractivePromptsEmail(t *testing.T) {
	e := newEnv(t)
	r := e.run("raoul@example.com\n", "register", "maison", "cam1=192.168.1.20:8080")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s %s", r.exit, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "Enter your email address") || !strings.Contains(r.stdout, "Register successful") {
		t.Fatalf("stdout %q", r.stdout)
	}
	if e.config(KEY_LE_EMAIL) != "raoul@example.com" {
		t.Fatal("prompted email not stored")
	}
	if h := e.backend.host("maison"); h.subzones != "cam1" {
		t.Fatalf("subzones %q", h.subzones)
	}
	st := e.state()
	if len(st.Subdomains) != 1 || st.Subdomains[0] != (Subdomain{Name: "cam1", IP: "192.168.1.20", Port: "8080"}) {
		t.Fatalf("subdomains %+v", st.Subdomains)
	}
	cfg, _ := os.ReadFile(e.path("haproxy", "haproxy.cfg"))
	if !strings.Contains(string(cfg), "use_backend cam1 if { ssl_fc_sni cam1.maison.calaos.fr }") {
		t.Fatalf("haproxy.cfg:\n%s", cfg)
	}
}

func TestRegisterJSONNeverPrompts(t *testing.T) {
	e := newEnv(t)
	r := e.run("raoul@example.com\n", "--json", "register", "maison")
	if r.exit != exitLocal || r.code() != codeNoEmail {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
	if e.config(KEY_LE_EMAIL) != "" {
		t.Fatal("--json read an e-mail from stdin")
	}
	// The name is registered and its token kept, so that it can be unregistered.
	if h := e.backend.host("maison"); h == nil || e.config(KEY_TOKEN) != h.token {
		t.Fatal("token not kept after a registration without certificate")
	}
	if len(e.acme.calls) != 0 {
		t.Fatal("ACME called without e-mail")
	}
}

func TestRegisterErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *testEnv)
		args  []string
		exit  int
		code  string
	}{
		{"host taken", func(e *testEnv) { e.backend.add("maison", otherToken, "") },
			[]string{"register", "maison"}, exitRefused, codeHostTaken},
		{"wrong token", func(e *testEnv) { e.backend.add("maison", otherToken, ""); e.setConfig(KEY_TOKEN, testToken) },
			[]string{"register", "maison"}, exitRefused, codeWrongToken},
		{"backend invalid name", nil,
			[]string{"register", "admin"}, exitRefused, codeInvalidName},
		{"local invalid sub-domain", nil,
			[]string{"register", "abcd", "x"}, exitLocal, codeInvalidName},
		{"local invalid name", nil,
			[]string{"register", "Bad!"}, exitLocal, codeInvalidName},
		{"domain=ip:port with json", nil,
			[]string{"register", "maison=10.0.0.1:80"}, exitLocal, codeInvalidName},
		{"bad email", nil,
			[]string{"register", "maison", "--email", "a&b@example.com"}, exitLocal, codeNoEmail},
		{"backend 502", func(e *testEnv) { e.backend.setFail(http.StatusBadGateway) },
			[]string{"register", "maison"}, exitUnreachable, codeBackendUnreachable},
		{"backend down", func(e *testEnv) { e.server.Close() },
			[]string{"register", "maison"}, exitUnreachable, codeBackendUnreachable},
		{"acme failed", func(e *testEnv) { e.acme.err = errors.New("acme: urn:ietf:params:acme:error:rateLimited") },
			[]string{"register", "maison"}, exitCert, codeAcmeFailed},
		{"dns propagation", func(e *testEnv) { e.acme.err = errPropagation },
			[]string{"register", "maison"}, exitCert, codeDNSPropagation},
		{"usage", nil,
			[]string{"register"}, exitLocal, codeInternal},
		{"unknown command", nil,
			[]string{"frobnicate"}, exitLocal, codeInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.setup != nil {
				c.setup(e)
			}
			args := append([]string{"--json"}, c.args...)
			if c.args[0] == "register" && len(c.args) > 1 && !strings.Contains(strings.Join(c.args, " "), "--email") {
				args = append(args, "--email", "raoul@example.com")
			}
			r := e.run("", args...)
			if r.exit != c.exit || r.code() != c.code {
				t.Fatalf("exit %d code %q, want %d %q (stderr %s)", r.exit, r.code(), c.exit, c.code, r.stderr)
			}
			if got := e.config("smtp_password"); got != smtpPassword {
				t.Fatalf("smtp_password altered: %q", got)
			}
		})
	}
}

func TestRegisterACMEFailureKeepsTokenAndRecordsIt(t *testing.T) {
	e := newEnv(t)
	e.acme.err = errPropagation
	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.code() != codeDNSPropagation {
		t.Fatalf("code %s", r.code())
	}
	if e.config(KEY_TOKEN) == "" {
		t.Fatal("token lost")
	}
	st := e.state()
	if st.Domain != "maison" || st.LastCert == nil || st.LastCert.OK || st.LastCert.Code != codeDNSPropagation {
		t.Fatalf("state %+v %+v", st, st.LastCert)
	}
}

func TestRegisterConfigWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e := newEnv(t)
	os.Chmod(e.path("config"), 0500)
	defer os.Chmod(e.path("config"), 0700)

	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.exit != exitLocal || r.code() != codeConfigWrite {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
}

func TestRegisterRefusesUnparseableConfig(t *testing.T) {
	e := newEnv(t)
	broken := `<calaos:config><calaos:option name="smtp_password" value="a&b" /></calaos:config>`
	e.writeConfig(broken)

	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.exit != exitLocal {
		t.Fatalf("exit %d", r.exit)
	}
	b, _ := os.ReadFile(e.path("config", "local_config.xml"))
	if string(b) != broken {
		t.Fatalf("unparseable file was rewritten: %s", b)
	}
	if e.backend.host("maison") != nil {
		t.Fatal("registered although the token could not be read")
	}
}

func TestRegisterTokenStdin(t *testing.T) {
	e := newEnv(t)
	e.backend.add("maison", testToken, "")

	r := e.run(testToken+"\n", "--json", "register", "maison", "--email", "raoul@example.com", "--token-stdin")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	if e.backend.body(0).Token != testToken {
		t.Fatal("stdin token not sent")
	}
	if e.config(KEY_TOKEN) != testToken {
		t.Fatal("token not stored")
	}

	r = e.run("not-a-token\n", "--json", "register", "maison", "--token-stdin")
	if r.exit != exitLocal || r.code() != codeWrongToken {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
}

func TestRegisterRepairKeepsSubdomains(t *testing.T) {
	e := newEnv(t)
	e.registered()

	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	body := e.backend.body(0)
	if body.Token != testToken || body.Subzones != "cam1" {
		t.Fatalf("repair sent %+v", body)
	}
	st := e.state()
	if st.RegisteredAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("registered_at changed on repair: %s", st.RegisteredAt)
	}
	cfg, _ := os.ReadFile(e.path("haproxy", "haproxy.cfg"))
	if !strings.Contains(string(cfg), "server cam1-server 192.168.1.20:8080") {
		t.Fatalf("proxied sub-domain dropped:\n%s", cfg)
	}
}

func TestRepairWithoutStateUsesServedCert(t *testing.T) {
	e := newEnv(t)
	e.registered()
	os.Remove(e.path("cache", "state.json"))
	os.WriteFile(e.path("haproxy", "haproxy.cfg"), []byte("backend cam1\n\tserver cam1-server 192.168.1.20:8080 check\n"), 0644)

	r := e.run("", "--json", "register", "maison", "--email", "raoul@example.com")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	if body := e.backend.body(0); body.Subzones != "cam1" {
		t.Fatalf("repair sent %+v", body)
	}
	st := e.state()
	if len(st.Subdomains) != 1 || st.Subdomains[0].IP != "192.168.1.20" {
		t.Fatalf("subdomains %+v", st.Subdomains)
	}
}

func TestChange(t *testing.T) {
	e := newEnv(t)
	e.registered()

	r := e.run("", "--json", "change", "nouveau")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	if e.backend.body(0).Token != "" || e.backend.body(0).Mainzone != "nouveau" || e.backend.body(0).Subzones != "cam1" {
		t.Fatalf("register body %+v", e.backend.body(0))
	}
	h := e.backend.host("nouveau")
	if e.backend.host("maison") != nil {
		t.Fatal("old name not deleted")
	}
	if e.config(KEY_TOKEN) != h.token {
		t.Fatal("token not swapped")
	}
	call := e.acme.last()
	if call.token != h.token || strings.Join(call.domains, ",") != "nouveau.calaos.fr,cam1.nouveau.calaos.fr" {
		t.Fatalf("ACME %+v", call)
	}
	if r.json["old_deleted"] != true {
		t.Fatalf("result %v", r.json)
	}
	st := e.state()
	if st.Domain != "nouveau" || len(st.Subdomains) != 1 || st.Subdomains[0].Port != "8080" {
		t.Fatalf("state %+v", st)
	}
	cfg, _ := os.ReadFile(e.path("haproxy", "haproxy.cfg"))
	if !strings.Contains(string(cfg), "ssl_fc_sni cam1.nouveau.calaos.fr") {
		t.Fatalf("haproxy.cfg:\n%s", cfg)
	}
	// The delete of the old name comes after the new registration.
	reqs := strings.Join(e.backend.reqs(), "|")
	if !strings.HasPrefix(reqs, "POST /api/register|DELETE /api/delete/"+testToken) {
		t.Fatalf("requests %s", reqs)
	}
}

func TestChangeFailureKeepsOldRegistration(t *testing.T) {
	for name, setup := range map[string]func(e *testEnv){
		"taken":   func(e *testEnv) { e.backend.add("nouveau", otherToken, "") },
		"acme":    func(e *testEnv) { e.acme.err = errors.New("acme failed") },
		"propag":  func(e *testEnv) { e.acme.err = errPropagation },
		"backend": func(e *testEnv) { e.backend.setFail(http.StatusServiceUnavailable) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered()
			pem, _ := os.ReadFile(e.path("haproxy", "server.pem"))
			cache, _ := os.ReadFile(e.path("cache", "cert.pem"))
			cfgBefore, _ := os.ReadFile(e.path("haproxy", "haproxy.cfg"))
			setup(e)

			r := e.run("", "--json", "change", "nouveau")
			if r.exit == 0 {
				t.Fatal("change succeeded")
			}
			e.backend.setFail(0)
			if h := e.backend.host("maison"); h == nil || h.token != testToken {
				t.Fatal("old registration touched")
			}
			if name != "taken" && e.backend.host("nouveau") != nil {
				t.Fatal("new name left registered after the failure")
			}
			if e.config(KEY_TOKEN) != testToken {
				t.Fatal("token swapped")
			}
			if e.state().Domain != "maison" {
				t.Fatal("state changed")
			}
			if b, _ := os.ReadFile(e.path("haproxy", "server.pem")); !bytes.Equal(b, pem) {
				t.Fatal("served certificate changed")
			}
			if b, _ := os.ReadFile(e.path("cache", "cert.pem")); !bytes.Equal(b, cache) {
				t.Fatal("cached certificate changed")
			}
			if b, _ := os.ReadFile(e.path("haproxy", "haproxy.cfg")); !bytes.Equal(b, cfgBefore) {
				t.Fatal("haproxy.cfg changed")
			}
		})
	}
}

func TestChangeLocalRefusals(t *testing.T) {
	e := newEnv(t)
	if r := e.run("", "--json", "change", "nouveau"); r.exit != exitLocal || r.code() != codeUnknownToken {
		t.Fatalf("no token: exit %d code %s", r.exit, r.code())
	}
	e.registered()
	if r := e.run("", "--json", "change", "x"); r.exit != exitLocal || r.code() != codeInvalidName {
		t.Fatalf("bad name: exit %d code %s", r.exit, r.code())
	}
	e.setConfig(KEY_LE_EMAIL, "")
	if r := e.run("", "--json", "change", "nouveau"); r.exit != exitLocal || r.code() != codeNoEmail {
		t.Fatalf("no email: exit %d code %s", r.exit, r.code())
	}
	if len(e.backend.reqs()) != 0 {
		t.Fatal("a local refusal called the backend")
	}
}

func TestUnregister(t *testing.T) {
	e := newEnv(t)
	e.registered()

	r := e.run("", "--json", "unregister")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	if e.backend.host("maison") != nil || e.config(KEY_TOKEN) != "" {
		t.Fatal("not unregistered")
	}
	if st := e.state(); st.Domain != "" || len(st.Subdomains) != 0 {
		t.Fatalf("state %+v", st)
	}
	if e.config("smtp_password") != smtpPassword {
		t.Fatal("smtp_password altered")
	}

	r = e.run("", "--json", "unregister")
	if r.exit != exitLocal || r.code() != codeUnknownToken {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
}

func TestUnregisterUnknownTokenThenLocal(t *testing.T) {
	e := newEnv(t)
	e.registered()
	e.backend.mu.Lock()
	delete(e.backend.hosts, "maison")
	e.backend.mu.Unlock()

	r := e.run("", "--json", "unregister")
	if r.exit != exitRefused || r.code() != codeUnknownToken {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
	if e.config(KEY_TOKEN) != testToken {
		t.Fatal("token dropped on a refusal")
	}

	n := len(e.backend.reqs())
	r = e.run("", "--json", "unregister", "--local")
	if r.exit != 0 || e.config(KEY_TOKEN) != "" {
		t.Fatalf("exit %d", r.exit)
	}
	if len(e.backend.reqs()) != n {
		t.Fatal("--local called the backend")
	}
	if e.state().Domain != "" {
		t.Fatal("state kept the domain")
	}

	e.setConfig(KEY_TOKEN, testToken)
	if r := e.run("", "reset"); r.exit != 0 || e.config(KEY_TOKEN) != "" {
		t.Fatalf("reset: exit %d", r.exit)
	}
}

func TestUpdateWithoutToken(t *testing.T) {
	e := newEnv(t)
	r := e.run("", "--json", "update")
	if r.exit != 0 || r.json["updated"] != false {
		t.Fatalf("exit %d %v", r.exit, r.json)
	}
	if len(e.backend.reqs()) != 0 {
		t.Fatal("backend called without token")
	}
	// The timer's plain output is unchanged.
	r = e.run("", "update")
	if r.exit != 0 || !strings.Contains(r.stdout, "No DDNS registration found. Nothing to update.") {
		t.Fatalf("exit %d %q", r.exit, r.stdout)
	}
}

func TestUpdate(t *testing.T) {
	e := newEnv(t)
	e.registered()

	r := e.run("", "update")
	if r.exit != 0 || !strings.Contains(r.stdout, "Update successful.") {
		t.Fatalf("exit %d %q %q", r.exit, r.stdout, r.stderr)
	}
	if reqs := e.backend.reqs(); len(reqs) != 1 || reqs[0] != "GET /api/update/"+testToken {
		t.Fatalf("requests %v", reqs)
	}
	st := e.state()
	if st.LastUpdate == nil || !st.LastUpdate.OK || st.LastCert != nil {
		t.Fatalf("state %+v", st)
	}
	if e.restarts != 0 || e.acme.renews != 1 {
		t.Fatalf("restarts %d renews %d", e.restarts, e.acme.renews)
	}

	r = e.run("", "--json", "update", "-f")
	if r.exit != 0 || r.json["renewed"] != true || e.restarts != 1 {
		t.Fatalf("exit %d %v restarts %d", r.exit, r.json, e.restarts)
	}
	if c := e.acme.last(); c.token != testToken || c.email != "raoul@example.com" {
		t.Fatalf("renew %+v", c)
	}
	if st := e.state(); st.LastCert == nil || !st.LastCert.OK || !st.LastCert.Renewed {
		t.Fatalf("last_cert %+v", st.LastCert)
	}
}

func TestUpdateErrors(t *testing.T) {
	e := newEnv(t)
	e.registered()
	e.setConfig(KEY_TOKEN, otherToken)

	r := e.run("", "--json", "update")
	if r.exit != exitRefused || r.code() != codeUnknownToken {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
	if st := e.state(); st.LastUpdate == nil || st.LastUpdate.OK || st.LastUpdate.Code != codeUnknownToken {
		t.Fatalf("last_update %+v", st.LastUpdate)
	}
	if e.acme.renews != 0 {
		t.Fatal("renewal attempted after a failed update")
	}

	e.setConfig(KEY_TOKEN, testToken)
	e.acme.err = errors.New("acme down")
	r = e.run("", "--json", "update", "-f")
	if r.exit != exitCert || r.code() != codeAcmeFailed {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
	if st := e.state(); st.LastCert == nil || st.LastCert.OK || st.LastCert.Code != codeAcmeFailed {
		t.Fatalf("last_cert %+v", st.LastCert)
	}
}

func TestUpdateRepairsMissingCertificate(t *testing.T) {
	e := newEnv(t)
	e.registered()
	for _, f := range []string{"cert.pem", "key.pem", "cert_key.pem", "CertResource.json"} {
		os.Remove(e.path("cache", f))
	}

	r := e.run("", "--json", "update")
	if r.exit != 0 || r.json["renewed"] != true {
		t.Fatalf("exit %d %v %s", r.exit, r.json, r.stderr)
	}
	call := e.acme.last()
	if strings.Join(call.domains, ",") != "maison.calaos.fr,cam1.maison.calaos.fr" || call.token != testToken {
		t.Fatalf("ACME %+v", call)
	}
	if e.restarts != 1 {
		t.Fatal("haproxy not restarted after the repair")
	}

	// Without an e-mail the repair is impossible.
	for _, f := range []string{"cert.pem", "key.pem"} {
		os.Remove(e.path("cache", f))
	}
	e.setConfig(KEY_LE_EMAIL, "")
	r = e.run("", "--json", "update")
	if r.exit != exitLocal || r.code() != codeNoEmail {
		t.Fatalf("exit %d code %s", r.exit, r.code())
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	e.registered()
	e.run("", "update")

	r := e.run("", "status", "--json")
	if r.exit != 0 {
		t.Fatalf("exit %d %s", r.exit, r.stderr)
	}
	j := r.json
	if j["token_set"] != true || j["domain"] != "maison" || j["email"] != "r***@example.com" || j["email_set"] != true || j["dns_ip"] != "203.0.113.7" {
		t.Fatalf("status %v", j)
	}
	if strings.Contains(r.stdout, "raoul@") {
		t.Fatal("e-mail not masked")
	}
	c := j["cert"].(map[string]interface{})
	if c["issuer"] != "Fake Encrypt" || c["self_signed"] != false || c["not_after"] == "" {
		t.Fatalf("cert %v", c)
	}
	if lu := j["last_update"].(map[string]interface{}); lu["ok"] != true {
		t.Fatalf("last_update %v", lu)
	}
	if subs := j["subdomains"].([]interface{}); len(subs) != 1 {
		t.Fatalf("subdomains %v", subs)
	}
	if len(e.backend.reqs()) != 1 {
		t.Fatal("status called the backend")
	}
}

func TestStatusNotRegistered(t *testing.T) {
	e := newEnv(t)
	// The self-signed certificate of a fresh box tells nothing about a domain.
	_, certPEM := makeCertPEM([]string{"maison.calaos.fr"}, true, time.Hour)
	os.WriteFile(e.path("haproxy", "server.pem"), certPEM, 0600)
	e.setConfig(KEY_TOKEN, testToken)

	r := e.run("", "--json", "status")
	j := r.json
	if r.exit != 0 || j["token_set"] != true || j["domain"] != "" || j["dns_ip"] != "" || j["email"] != "" {
		t.Fatalf("status %v", j)
	}
	if c := j["cert"].(map[string]interface{}); c["self_signed"] != true {
		t.Fatalf("cert %v", c)
	}
	if j["last_update"] != nil || j["last_cert"] != nil {
		t.Fatalf("status %v", j)
	}
}

func TestStatusInfersDomainFromServedCert(t *testing.T) {
	e := newEnv(t)
	e.registered()
	os.Remove(e.path("cache", "state.json"))

	r := e.run("", "--json", "status")
	if r.json["domain"] != "maison" || r.json["dns_ip"] != "203.0.113.7" {
		t.Fatalf("status %v", r.json)
	}
	if _, err := os.Stat(e.path("cache", "state.json")); err == nil {
		t.Fatal("status wrote the state")
	}
}

func TestStatusDNSTimeout(t *testing.T) {
	e := newEnv(t)
	e.registered()
	nsDNSAddr = "127.0.0.1:9"
	start := time.Now()
	r := e.run("", "--json", "status")
	if r.exit != 0 || r.json["dns_ip"] != "" {
		t.Fatalf("status %v", r.json)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("dns_ip lookup not bounded")
	}
}

func TestBusyInProcess(t *testing.T) {
	e := newEnv(t)
	e.registered()

	unlock, busy, err := runLock()
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	defer unlock()

	for _, args := range [][]string{
		{"--json", "update"},
		{"--json", "register", "maison", "--email", "raoul@example.com"},
		{"--json", "change", "nouveau"},
		{"--json", "unregister"},
		{"--json", "unregister", "--local"},
		{"--json", "reset"},
	} {
		r := e.run("", args...)
		if r.exit != exitBusy || r.code() != codeBusy {
			t.Fatalf("%v: exit %d code %s", args, r.exit, r.code())
		}
	}
	if len(e.backend.reqs()) != 0 || e.config(KEY_TOKEN) != testToken {
		t.Fatal("a busy run did something")
	}
	if r := e.run("", "--json", "status"); r.exit != 0 {
		t.Fatalf("status blocked by the run lock: %d", r.exit)
	}
}

func TestHelpAndVersion(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{{"--help"}, {"--version"}, {"register", "--help"}, {}} {
		if r := e.run("", args...); r.exit != 0 || r.stdout != "" {
			t.Fatalf("%v: exit %d stdout %q", args, r.exit, r.stdout)
		}
	}
}

func child(t *testing.T, e *testEnv, stdin string, args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "CALAOS_DDNS_TEST_CHILD=1", "CALAOS_DDNS_TEST_NS="+e.server.URL+"/")
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// Two real processes: the second one exits 5 while the first runs, status
// still answers, and neither truncates the first one's log.
func TestConcurrentRunsExitBusy(t *testing.T) {
	e := newEnv(t)
	e.registered()
	block, entered := make(chan struct{}), make(chan struct{})
	e.backend.mu.Lock()
	e.backend.block, e.backend.entered = block, entered
	e.backend.mu.Unlock()

	first := child(t, e, "", "--json", "update")
	var firstOut bytes.Buffer
	first.Stdout = &firstOut
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("first run never reached the backend")
	}

	out, err := child(t, e, "", "--json", "update").Output()
	if exitCode(err) != exitBusy {
		t.Fatalf("second run: exit %d %s", exitCode(err), out)
	}
	var j map[string]interface{}
	if json.Unmarshal(out, &j) != nil || j["ok"] != false || j["error"].(map[string]interface{})["code"] != codeBusy {
		t.Fatalf("second run output %s", out)
	}

	out, err = child(t, e, "", "status", "--json").Output()
	if exitCode(err) != 0 {
		t.Fatalf("status during a run: exit %d %s", exitCode(err), out)
	}

	close(block)
	if err := first.Wait(); err != nil {
		t.Fatalf("first run: %v %s", err, firstOut.String())
	}

	logb, _ := os.ReadFile(e.path("cache", "calaos_ddns.log"))
	if !strings.Contains(string(logb), "Updating IP address") {
		t.Fatalf("log of the running command was truncated: %q", logb)
	}
	if strings.Contains(string(logb), testToken) {
		t.Fatal("token in the log file")
	}
}

// Every exit code through a real process, as systemd and the daemon see it.
func TestExitCodesSubprocess(t *testing.T) {
	cases := []struct {
		setup func(e *testEnv)
		args  []string
		exit  int
	}{
		{func(e *testEnv) { e.registered() }, []string{"--json", "update"}, exitOK},
		{nil, []string{"--json", "register"}, exitLocal},
		{func(e *testEnv) { e.backend.add("maison", otherToken, "") }, []string{"--json", "register", "maison", "--email", "a@example.com"}, exitRefused},
		{func(e *testEnv) { e.registered(); e.backend.setFail(http.StatusBadGateway) }, []string{"--json", "update"}, exitUnreachable},
		{func(e *testEnv) {
			e.registered()
			os.Remove(e.path("cache", "cert.pem"))
			os.Remove(e.path("cache", "state.json"))
			os.Remove(e.path("haproxy", "server.pem"))
		}, []string{"--json", "update"}, exitCert},
	}
	for _, c := range cases {
		e := newEnv(t)
		if c.setup != nil {
			c.setup(e)
		}
		out, err := child(t, e, "", c.args...).Output()
		if exitCode(err) != c.exit {
			t.Fatalf("%v: exit %d want %d: %s", c.args, exitCode(err), c.exit, out)
		}
		e.assertNoSecret(string(out))
	}

	// exit 5: hold the run lock from this process.
	e := newEnv(t)
	unlock, _, _ := runLock()
	defer unlock()
	if _, err := child(t, e, "", "update").Output(); exitCode(err) != exitBusy {
		t.Fatalf("busy: exit %d", exitCode(err))
	}
}

func TestTimerUnitAcceptsBusy(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoDir(), "debian", "calaos-ddns.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "SuccessExitStatus=5") || !strings.Contains(string(b), "ExecStart=/usr/bin/calaos_ddns update\n") {
		t.Fatalf("unit:\n%s", b)
	}
}

func TestDNSProviderUsesGivenToken(t *testing.T) {
	// The DNS-01 provider gets the token as a parameter, not from the config.
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var j calaosdns.LeJson
		json.NewDecoder(r.Body).Decode(&j)
		got = j.Token
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	saved := calaosdns.BaseURL
	calaosdns.BaseURL = srv.URL + "/"
	defer func() { calaosdns.BaseURL = saved }()

	p, err := calaosdns.NewDNSProvider(otherToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present("nouveau.calaos.fr", "", "keyauth"); err != nil || got != otherToken {
		t.Fatalf("present: %v token %q", err, got)
	}
}
