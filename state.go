package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/calaos/calaos_dns/utils"
	"github.com/xenolf/lego/platform/config/env"
)

const stateFile = "state.json"

type Subdomain struct {
	Name string `json:"name"`
	IP   string `json:"ip,omitempty"`
	Port string `json:"port,omitempty"`
}

type RunResult struct {
	At   string `json:"at"`
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

type CertResult struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Renewed bool   `json:"renewed"`
}

// State is what the backend knows about this box, kept locally because the
// backend has no read API.
type State struct {
	Domain       string      `json:"domain"`
	Subdomains   []Subdomain `json:"subdomains"`
	EmailSet     bool        `json:"email_set"`
	RegisteredAt string      `json:"registered_at,omitempty"`
	LastUpdate   *RunResult  `json:"last_update"`
	LastCert     *CertResult `json:"last_cert"`
}

var nowFunc = time.Now

func nowString() string {
	return nowFunc().UTC().Format(time.RFC3339)
}

func statePath() string {
	return filepath.Join(utils.CreateCacheDir(), stateFile)
}

// loadState returns found=false when there is no usable state file.
func loadState() (st State, found bool) {
	b, err := ioutil.ReadFile(statePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Println("Failed to read state:", err)
		}
		return State{}, false
	}
	if err := json.Unmarshal(b, &st); err != nil {
		log.Println("Ignoring corrupted state file:", err)
		return State{}, false
	}
	return st, true
}

// loadOrInferState falls back to the served certificate for a registration
// made before the state file existed, or restored without it.
func loadOrInferState() State {
	if st, found := loadState(); found {
		return st
	}
	return inferState(readServedCert())
}

func saveState(st State) error {
	if st.Subdomains == nil {
		st.Subdomains = []Subdomain{}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(), append(b, '\n'), 0600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := ioutil.TempFile(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (st State) subdomainArgs() []string {
	var args []string
	for _, s := range st.Subdomains {
		if s.IP != "" && s.Port != "" {
			args = append(args, s.Name+"="+s.IP+":"+s.Port)
		} else {
			args = append(args, s.Name)
		}
	}
	return args
}

func (st State) certDomains() []string {
	d := []string{st.Domain + ".calaos.fr"}
	for _, s := range st.Subdomains {
		d = append(d, s.Name+"."+st.Domain+".calaos.fr")
	}
	return d
}

type certInfo struct {
	Issuer     string   `json:"issuer"`
	SelfSigned bool     `json:"self_signed"`
	Names      []string `json:"names"`
	NotAfter   string   `json:"not_after"`
}

func certFile() string {
	return env.GetOrDefaultString("CALAOS_CERT_FILE", "/etc/ssl/haproxy/server.pem")
}

// readServedCert reads the first certificate of the PEM served by haproxy.
func readServedCert() *certInfo {
	b, err := ioutil.ReadFile(certFile())
	if err != nil {
		return nil
	}

	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}

		ci := &certInfo{
			Issuer:   c.Issuer.CommonName,
			Names:    c.DNSNames,
			NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		}
		if len(c.Issuer.Organization) > 0 {
			ci.Issuer = c.Issuer.Organization[0]
		}
		if len(ci.Names) == 0 && c.Subject.CommonName != "" {
			ci.Names = []string{c.Subject.CommonName}
		}
		// CheckSignatureFrom would demand CA:TRUE, which a self-signed leaf may lack.
		ci.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) &&
			c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
		return ci
	}
}

var (
	mainNameRe = regexp.MustCompile(`^([a-z0-9]{4,32})\.calaos\.fr$`)
	subNameRe  = regexp.MustCompile(`^([a-z0-9]{2,32})\.([a-z0-9]{4,32})\.calaos\.fr$`)
	serverRe   = regexp.MustCompile(`^\s*server\s+(\S+)-server\s+([^\s:]+):(\d+)`)
)

func inferState(ci *certInfo) State {
	st := State{}
	if ci == nil || ci.SelfSigned {
		return st
	}

	for _, n := range ci.Names {
		if m := mainNameRe.FindStringSubmatch(n); m != nil {
			st.Domain = m[1]
			break
		}
	}
	if st.Domain == "" {
		return st
	}

	backends := haproxyBackends()
	for _, n := range ci.Names {
		m := subNameRe.FindStringSubmatch(n)
		if m == nil || m[2] != st.Domain {
			continue
		}
		s := Subdomain{Name: m[1]}
		if b, ok := backends[m[1]]; ok {
			s.IP, s.Port = b[0], b[1]
		}
		st.Subdomains = append(st.Subdomains, s)
	}

	return st
}

func haproxyCfgPath() string {
	return filepath.Join(env.GetOrDefaultString("CALAOS_HAPROXY_PATH", "/etc/haproxy"), "haproxy.cfg")
}

// haproxyBackends reads the SNI backends of a haproxy.cfg rendered by this
// tool, so that a repair does not drop the proxied sub-domains.
func haproxyBackends() map[string][2]string {
	res := map[string][2]string{}
	f, err := os.Open(haproxyCfgPath())
	if err != nil {
		return res
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := serverRe.FindStringSubmatch(sc.Text()); m != nil && m[1] != "calaos" {
			res[m[1]] = [2]string{m[2], m[3]}
		}
	}
	return res
}

// runLock is held for the whole run of every command but status, so that a
// manual or daemon run never overlaps the timer.
func runLock() (unlock func(), busy bool, err error) {
	path := filepath.Join(utils.CreateCacheDir(), "calaos_ddns.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, false, err
	}

	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if err == syscall.EWOULDBLOCK {
		f.Close()
		return nil, true, nil
	}
	if err != nil {
		f.Close()
		return nil, false, err
	}

	return func() { f.Close() }, false, nil
}

func maskEmail(e string) string {
	i := strings.LastIndexByte(e, '@')
	if i <= 0 {
		return ""
	}
	r := []rune(e[:i])
	return string(r[0]) + "***" + e[i:]
}
