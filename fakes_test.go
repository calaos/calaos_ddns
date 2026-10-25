package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calaos/calaos_ddns/calaos"
	"github.com/calaos/calaos_ddns/cert/calaosdns"
	"github.com/miekg/dns"
)

// fakeBackend mimics calaos_dns: same routes, same 400 messages.
type fakeBackend struct {
	mu       sync.Mutex
	hosts    map[string]*fakeHost // by name
	requests []string
	bodies   []RegisterJson
	fail     int           // HTTP status forced on every request
	block    chan struct{} // when set, api/update waits on it
	entered  chan struct{} // closed when api/update is entered
	next     int
}

type fakeHost struct {
	token    string
	subzones string
}

var fakeNameRe = regexp.MustCompile(`^[a-z0-9]{4,32}$`)

func newFakeBackend() *fakeBackend {
	return &fakeBackend{hosts: map[string]*fakeHost{}}
}

func (f *fakeBackend) add(name, token, subzones string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[name] = &fakeHost{token: token, subzones: subzones}
}

func (f *fakeBackend) setFail(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = status
}

func (f *fakeBackend) host(name string) *fakeHost {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hosts[name]
}

func (f *fakeBackend) body(i int) RegisterJson {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bodies) {
		return RegisterJson{Mainzone: "<none>"}
	}
	return f.bodies[i]
}

func (f *fakeBackend) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeBackend) byToken(token string) string {
	for n, h := range f.hosts {
		if h.token == token {
			return n
		}
	}
	return ""
}

func refuse(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `{"message":%q}`, msg)
}

func (f *fakeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	fail, block, entered := f.fail, f.block, f.entered
	f.mu.Unlock()

	if fail != 0 {
		w.WriteHeader(fail)
		fmt.Fprint(w, "<html>bad gateway</html>")
		return
	}

	switch {
	case r.Method == "POST" && r.URL.Path == "/api/register":
		var req RegisterJson
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.bodies = append(f.bodies, req)
		if !fakeNameRe.MatchString(req.Mainzone) || req.Mainzone == "admin" {
			refuse(w, "Invalid hostname")
			return
		}
		h := f.hosts[req.Mainzone]
		if req.Token == "" {
			if h != nil {
				refuse(w, "Host already registered")
				return
			}
			f.next++
			h = &fakeHost{token: fmt.Sprintf("%016x", 0xabc000+f.next)}
			f.hosts[req.Mainzone] = h
		} else if h == nil || h.token != req.Token {
			refuse(w, "Wrong token")
			return
		}
		h.subzones = req.Subzones
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(RegisterJson{Mainzone: req.Mainzone, Subzones: req.Subzones, Token: h.token})

	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/update/"):
		if entered != nil {
			close(entered)
		}
		if block != nil {
			<-block
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.byToken(strings.TrimPrefix(r.URL.Path, "/api/update/")) == "" {
			refuse(w, "Unknown token")
			return
		}
		w.WriteHeader(http.StatusOK)

	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/delete/"):
		f.mu.Lock()
		defer f.mu.Unlock()
		n := f.byToken(strings.TrimPrefix(r.URL.Path, "/api/delete/"))
		if n == "" {
			refuse(w, "Unknown token")
			return
		}
		delete(f.hosts, n)
		w.WriteHeader(http.StatusOK)

	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}
}

// fakeACME replaces Let's Encrypt: it signs certificates with a test CA.
type fakeACME struct {
	mu     sync.Mutex
	calls  []acmeCall
	err    error
	renews int
	due    bool
}

type acmeCall struct {
	domains []string
	email   string
	token   string
}

var (
	testCAOnce sync.Once
	testCA     *x509.Certificate
	testCAKey  *ecdsa.PrivateKey
)

func caCert() (*x509.Certificate, *ecdsa.PrivateKey) {
	testCAOnce.Do(func() {
		testCAKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Fake R3", Organization: []string{"Fake Encrypt"}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testCAKey.PublicKey, testCAKey)
		testCA, _ = x509.ParseCertificate(der)
	})
	return testCA, testCAKey
}

// makeCertPEM returns key PEM and cert PEM for names, signed by the test CA
// (or self-signed).
func makeCertPEM(names []string, selfSigned bool, validity time.Duration) (keyPEM, certPEM []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
	}
	parent, parentKey := caCert()
	if selfSigned {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		panic(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return
}

func writeCache(dir string, names []string, validity time.Duration) error {
	keyPEM, certPEM := makeCertPEM(names, false, validity)
	cr, _ := json.Marshal(map[string]interface{}{"domain": names[0], "domains": names})
	for f, b := range map[string][]byte{
		"cert.pem":          certPEM,
		"key.pem":           keyPEM,
		"cert_key.pem":      append(append([]byte{}, keyPEM...), certPEM...),
		"CertResource.json": cr,
	} {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeACME) generate(domains []string, email, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, acmeCall{domains: domains, email: email, token: token})
	if f.err != nil {
		return f.err
	}
	return writeCache(os.Getenv("CALAOSDNS_CACHE_DIR"), domains, 90*24*time.Hour)
}

func (f *fakeACME) renew(force bool, email, token string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews++
	if f.err != nil {
		return false, f.err
	}
	if !force && !f.due {
		return false, nil
	}
	f.calls = append(f.calls, acmeCall{email: email, token: token})
	return true, writeCache(os.Getenv("CALAOSDNS_CACHE_DIR"), []string{"maison.calaos.fr"}, 90*24*time.Hour)
}

func (f *fakeACME) last() acmeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return acmeCall{}
	}
	return f.calls[len(f.calls)-1]
}

func startFakeDNS(t testing.TB, answers map[string]string) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		if ip, ok := answers[q.Name]; ok && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		} else {
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

const smtpPassword = `p&ss"w<rd>'x`

type testEnv struct {
	t        *testing.T
	dir      string
	backend  *fakeBackend
	server   *httptest.Server
	acme     *fakeACME
	restarts int
}

func repoDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// newEnv points every path at a temp dir, every network peer at a fake.
func newEnv(t *testing.T) *testEnv {
	e := &testEnv{t: t, dir: t.TempDir(), backend: newFakeBackend(), acme: &fakeACME{}}
	for _, d := range []string{"config", "cache", "haproxy"} {
		if err := os.MkdirAll(filepath.Join(e.dir, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", e.dir)
	t.Setenv("CALAOS_CONFIG", filepath.Join(e.dir, "config"))
	t.Setenv("CALAOSDNS_CACHE_DIR", filepath.Join(e.dir, "cache"))
	t.Setenv("CALAOS_CERT_FILE", filepath.Join(e.dir, "haproxy", "server.pem"))
	t.Setenv("CALAOS_HAPROXY_PATH", filepath.Join(e.dir, "haproxy"))
	t.Setenv("CALAOS_HAPROXY_TEMPLATE_PATH", filepath.Join(repoDir(), "haproxy"))

	e.writeConfig(`<?xml version="1.0" encoding="UTF-8"?>
<calaos:config xmlns:calaos="http://www.calaos.fr">
    <calaos:option name="smtp_password" value="p&amp;ss&quot;w&lt;rd&gt;&apos;x" />
</calaos:config>
`)

	e.server = httptest.NewServer(e.backend)
	t.Cleanup(e.server.Close)

	saved := []interface{}{nsURL, calaosdns.BaseURL, nsDNSAddr, issueCert, renewCert, restartHaproxy}
	nsURL = e.server.URL + "/"
	calaosdns.BaseURL = nsURL
	nsDNSAddr = startFakeDNS(t, map[string]string{"maison.calaos.fr.": "203.0.113.7", "nouveau.calaos.fr.": "203.0.113.8"})
	issueCert = e.acme.generate
	renewCert = e.acme.renew
	restartHaproxy = func() error { e.restarts++; return nil }
	t.Cleanup(func() {
		nsURL = saved[0].(string)
		calaosdns.BaseURL = saved[1].(string)
		nsDNSAddr = saved[2].(string)
		issueCert = saved[3].(func([]string, string, string) error)
		renewCert = saved[4].(func(bool, string, string) (bool, error))
		restartHaproxy = saved[5].(func() error)
	})
	return e
}

func (e *testEnv) path(p ...string) string {
	return filepath.Join(append([]string{e.dir}, p...)...)
}

func (e *testEnv) writeConfig(s string) {
	if err := os.WriteFile(e.path("config", "local_config.xml"), []byte(s), 0600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *testEnv) config(key string) string {
	err, v := calaos.GetConfig(key)
	if err != nil {
		e.t.Fatalf("config %s: %v", key, err)
	}
	return v
}

func (e *testEnv) setConfig(key, v string) {
	if err := calaos.SetConfig(key, v); err != nil {
		e.t.Fatal(err)
	}
}

func (e *testEnv) state() State {
	b, err := os.ReadFile(e.path("cache", "state.json"))
	if err != nil {
		e.t.Fatalf("state: %v", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

type result struct {
	exit   int
	stdout string
	stderr string
	json   map[string]interface{}
}

func (r result) code() string {
	if e, ok := r.json["error"].(map[string]interface{}); ok {
		return e["code"].(string)
	}
	return ""
}

// run executes the CLI in-process and checks the --json contract: exactly
// one JSON object on stdout, ok consistent with the exit code, and no
// secret anywhere in the output.
func (e *testEnv) run(stdin string, args ...string) result {
	e.t.Helper()
	var out, errOut bytes.Buffer
	exit := run(append([]string{"calaos_ddns"}, args...), strings.NewReader(stdin), &out, &errOut)
	r := result{exit: exit, stdout: out.String(), stderr: errOut.String()}

	if wantJSON(append([]string{"calaos_ddns"}, args...)) {
		lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
		if len(lines) != 1 {
			e.t.Fatalf("want one JSON line on stdout, got %q (stderr %q)", r.stdout, r.stderr)
		}
		if err := json.Unmarshal([]byte(lines[0]), &r.json); err != nil {
			e.t.Fatalf("stdout is not JSON: %q", r.stdout)
		}
		if ok, _ := r.json["ok"].(bool); ok != (exit == 0) {
			e.t.Fatalf("ok=%v with exit %d: %s", ok, exit, r.stdout)
		}
		if exit != 0 {
			msg := r.json["error"].(map[string]interface{})["msg"]
			if msg != codes[r.code()].msg {
				e.t.Fatalf("msg %q is not the fixed text of %s", msg, r.code())
			}
		}
	}

	e.assertNoSecret(r.stdout + r.stderr)
	return r
}

func (e *testEnv) assertNoSecret(s string) {
	e.t.Helper()
	e.backend.mu.Lock()
	defer e.backend.mu.Unlock()
	for _, h := range e.backend.hosts {
		if strings.Contains(s, h.token) {
			e.t.Fatalf("token %s leaked in output: %q", h.token, s)
		}
	}
	for _, tok := range []string{testToken, otherToken} {
		if strings.Contains(s, tok) {
			e.t.Fatalf("token leaked in output: %q", s)
		}
	}
	if strings.Contains(s, smtpPassword) {
		e.t.Fatalf("smtp_password leaked: %q", s)
	}
}

const (
	testToken  = "00000000deadbeef"
	otherToken = "11111111deadbeef"
)

// registered sets up a box registered as maison (+cam1 proxied) with a
// certificate in cache and served.
func (e *testEnv) registered() {
	e.backend.add("maison", testToken, "cam1")
	e.setConfig(KEY_TOKEN, testToken)
	e.setConfig(KEY_LE_EMAIL, "raoul@example.com")
	if err := saveState(State{
		Domain:       "maison",
		Subdomains:   []Subdomain{{Name: "cam1", IP: "192.168.1.20", Port: "8080"}},
		EmailSet:     true,
		RegisteredAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		e.t.Fatal(err)
	}
	names := []string{"maison.calaos.fr", "cam1.maison.calaos.fr"}
	if err := writeCache(e.path("cache"), names, 80*24*time.Hour); err != nil {
		e.t.Fatal(err)
	}
	b, _ := os.ReadFile(e.path("cache", "cert_key.pem"))
	if err := os.WriteFile(e.path("haproxy", "server.pem"), b, 0600); err != nil {
		e.t.Fatal(err)
	}
}

var errPropagation = errors.New("acme: error: 400 :: urn:ietf:params:acme:error:dns :: time limit exceeded: last error: NXDOMAIN")
