package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/calaos/calaos_ddns/calaos"
	lecert "github.com/calaos/calaos_ddns/cert"
	"github.com/calaos/calaos_ddns/haproxy"
	"github.com/calaos/calaos_dns/utils"
	"github.com/fatih/color"
	cli "github.com/jawher/mow.cli"
	"github.com/mattn/go-isatty"
	legoLog "github.com/xenolf/lego/log"
	"github.com/xenolf/lego/platform/config/env"
)

const (
	CharStar     = "✷"
	CharAbort    = "✘"
	CharCheck    = "✔"
	CharWarning  = "⚠"
	CharArrow    = "‒▶"
	CharVertLine = "│"

	KEY_TOKEN    = "ddns_token"
	KEY_LE_EMAIL = "ddns_le_email"

	jsonHelp = "Print one JSON object on stdout at exit, never prompt"
)

var (
	errorRed = color.New(color.FgRed).SprintFunc()

	nameRe  = regexp.MustCompile(`^[a-z0-9]{4,32}$`)
	tokenRe = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	emailRe = regexp.MustCompile(`^[^\s@"'<>&;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

// Side effects that tests replace.
var (
	issueCert      = lecert.GenerateCert
	renewCert      = lecert.MaybeRenew
	certIsCached   = lecert.Cached
	snapshotCache  = lecert.SnapshotCache
	restartHaproxy = func() error {
		return exec.Command("/bin/systemctl", "restart", "haproxy.service").Run()
	}
)

func validToken(t string) bool { return tokenRe.MatchString(t) }

func validEmail(e string) bool { return len(e) <= 254 && emailRe.MatchString(e) }

type app struct {
	json    bool
	in      *bufio.Reader
	stdout  io.Writer
	stderr  io.Writer
	out     io.Writer // human messages
	result  map[string]interface{}
	err     *cmdError
	ran     bool
	secrets []string
}

func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}

// wantJSON is decided before parsing, so that a usage error is reported in
// JSON too.
func wantJSON(args []string) bool {
	for _, a := range args[1:] {
		if a == "--" {
			break
		}
		if a == "--json" || a == "--json=true" {
			return true
		}
	}
	return false
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	a := &app{
		json:   wantJSON(args),
		in:     bufio.NewReader(stdin),
		stdout: stdout,
		stderr: stderr,
		out:    stdout,
		result: map[string]interface{}{},
	}
	if a.json {
		a.out = stderr
	}

	defer func() {
		if r := recover(); r != nil {
			a.err = localErr(codeInternal, fmt.Errorf("panic: %v", r))
		}
		code = a.finish()
	}()

	mnApp := cli.App("calaos_ddns", "Client for Calaos Dynamic DNS API")
	mnApp.ErrorHandling = flag.ContinueOnError
	mnApp.Version("v version", "Calaos DDNS "+BuildVersion)
	mnApp.BoolOpt("json", false, jsonHelp)

	mnApp.Command("register", "Register a DNS record, or repair the current one", a.cmdRegister)
	mnApp.Command("change", "Move the registration to a new name", a.cmdChange)
	mnApp.Command("unregister", "Unregister the saved DNS record", a.cmdUnregister)
	mnApp.Command("update", "Update IP of DNS record", a.cmdUpdate)
	mnApp.Command("reset", "Reset an expired token (same as unregister --local)", a.cmdReset)
	mnApp.Command("status", "Show the registration and certificate state", a.cmdStatus)

	if err := mnApp.Run(args); err != nil {
		a.err = localErr(codeInternal, err)
	}
	return
}

func (a *app) finish() int {
	if a.err != nil {
		fmt.Fprintln(a.stderr, errorRed(CharAbort), a.scrub(a.err.Error()))
		if a.json {
			a.result["ok"] = false
			a.result["error"] = map[string]string{"code": a.err.code, "msg": codes[a.err.code].msg}
			a.writeJSON()
		}
		return a.err.exit
	}

	// --help and --version
	if !a.ran {
		return exitOK
	}

	if a.json {
		a.result["ok"] = true
		a.writeJSON()
	}
	return exitOK
}

func (a *app) writeJSON() {
	b, err := json.Marshal(a.result)
	if err != nil {
		b = []byte(`{"ok":false,"error":{"code":"internal","msg":"Internal error"}}`)
	}
	fmt.Fprintln(a.stdout, string(b))
}

func (a *app) addSecret(s string) {
	if s != "" {
		a.secrets = append(a.secrets, s)
	}
}

func (a *app) scrub(s string) string {
	for _, sec := range a.secrets {
		s = strings.Replace(s, sec, "***", -1)
	}
	return s
}

func (a *app) say(format string, args ...interface{}) {
	fmt.Fprintln(a.out, a.scrub(fmt.Sprintf(format, args...)))
}

func (a *app) success(msg string) {
	a.say("%s", color.GreenString(CharCheck+" "+msg))
}

func (a *app) interactive() bool {
	f, ok := a.stdout.(*os.File)
	return !a.json && ok && isatty.IsTerminal(f.Fd())
}

func (a *app) withSpinner(msg string, fn func() error) error {
	if !a.interactive() {
		return fn()
	}
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = "  " + msg
	s.Color("blue")
	s.Start()
	defer s.Stop()
	return fn()
}

// locked runs fn under the run lock. The log file is opened (and truncated)
// only once the lock is held, never under the feet of a running command.
func (a *app) locked(fn func() *cmdError) func() {
	return func() {
		a.ran = true
		unlock, busy, err := runLock()
		if err != nil {
			a.err = localErr(codeInternal, err)
			return
		}
		if busy {
			a.err = newErr(codeBusy, nil)
			return
		}
		defer unlock()

		_, logFile, err := utils.InitLogger()
		if err != nil {
			a.err = localErr(codeInternal, err)
			return
		}
		if a.json {
			legoLog.Logger = log.New(logFile, "", log.LstdFlags)
		}

		a.err = fn()
	}
}

func (a *app) getConfig(key string) (string, *cmdError) {
	err, v := calaos.GetConfig(key)
	if err != nil {
		return "", localErr(codeInternal, fmt.Errorf("reading calaos config: %v", err))
	}
	if key == KEY_TOKEN || key == KEY_LE_EMAIL {
		a.addSecret(v)
	}
	return v, nil
}

func (a *app) readLine(max int) string {
	var b []byte
	for len(b) <= max {
		c, err := a.in.ReadByte()
		if err != nil || c == '\n' {
			break
		}
		b = append(b, c)
	}
	return strings.TrimSpace(string(b))
}

func (a *app) saveState(st State) *cmdError {
	if err := saveState(st); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("writing state: %v", err))
	}
	return nil
}

// issue gets a certificate for st's names and records the attempt in st.
func (a *app) issue(st *State, email, token string) *cmdError {
	err := a.withSpinner("Getting a certificate from Let's Encrypt. Please wait...", func() error {
		return issueCert(st.certDomains(), email, token)
	})
	cerr := certError(err)
	st.LastCert = &CertResult{At: nowString(), OK: cerr == nil, Code: errCode(cerr), Renewed: cerr == nil}
	if serr := a.saveState(*st); serr != nil && cerr == nil {
		return serr
	}
	return cerr
}

func haproxyPaths() (templateFile, outFile string) {
	templateFile = filepath.Join(env.GetOrDefaultString("CALAOS_HAPROXY_TEMPLATE_PATH", "/etc/haproxy"), "haproxy.template")
	outFile = haproxyCfgPath()
	return
}

// installCert copies the cached certificate to the haproxy PEM and renders
// haproxy.cfg for haconf.
func installCert(haconf *haproxy.Config) *cmdError {
	if err := lecert.WritePemFile(certFile()); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("writing certificate: %v", err))
	}
	templateFile, outFile := haproxyPaths()
	if err := haproxy.RenderConfig(outFile, templateFile, haconf); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("writing haproxy config: %v", err))
	}
	return nil
}

func subdomainsOf(haconf *haproxy.Config) []Subdomain {
	var subs []Subdomain
	for _, b := range haconf.Backends[1:] {
		subs = append(subs, Subdomain{Name: b.Name, IP: b.Ip, Port: b.Port})
	}
	return subs
}

func subdomainNames(subs []Subdomain) []string {
	var names []string
	for _, s := range subs {
		names = append(names, s.Name)
	}
	return names
}

func (a *app) cmdRegister(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS] DOMAIN [SUBDOMAIN...] [OPTIONS]"
	var (
		email      = cmd.StringOpt("email", "", "Let's Encrypt e-mail address (no prompt)")
		tokenStdin = cmd.BoolOpt("token-stdin", false, "Read the token of an existing registration from stdin")
		_          = cmd.BoolOpt("json", false, jsonHelp)
		domain     = cmd.StringArg("DOMAIN", "", "The subdomain to register (ex. myname would register myname.calaos.fr)")
		subdomains = cmd.StringsArg("SUBDOMAIN", nil, "The subdomains to register under your maindomain (ex. camera1 would register camera1.myname.calaos.fr) camera1=192.168.0.1:4444 will also create a haproxy entry for pointing to the correct IP address")
	)

	cmd.Action = a.locked(func() *cmdError {
		return a.register(*domain, *subdomains, *email, *tokenStdin)
	})
}

func (a *app) register(domainArg string, subArgs []string, email string, tokenStdin bool) *cmdError {
	// DOMAIN=IP:PORT moves calaos_server off the https path: CLI use only.
	if a.json && strings.Contains(domainArg, "=") {
		return localErr(codeInvalidName, errors.New("DOMAIN=IP:PORT is not accepted with --json"))
	}
	if email != "" && !validEmail(email) {
		return localErr(codeNoEmail, errors.New("invalid e-mail address"))
	}
	a.addSecret(email)

	token, cerr := a.getConfig(KEY_TOKEN)
	if cerr != nil {
		return cerr
	}
	if tokenStdin {
		token = a.readLine(128)
		if !validToken(token) {
			return localErr(codeWrongToken, errors.New("the token read from stdin is not valid"))
		}
		a.addSecret(token)
	}

	st := loadOrInferState()

	// Repair: the backend replaces the sub-domain list on every register, so
	// re-send the known one when none is given.
	if token != "" && len(subArgs) == 0 && st.Domain != "" && st.Domain == domainArg {
		subArgs = st.subdomainArgs()
	}

	haconf, err := haproxy.ParseDomains(domainArg, subArgs)
	if err != nil {
		return localErr(codeInvalidName, err)
	}
	mainDomain := haconf.Backends[0].Name
	subs := subdomainsOf(haconf)
	a.result["domain"] = mainDomain

	newToken, cerr := a.backendRegister(mainDomain, subdomainNames(subs), token)
	if cerr != nil {
		return cerr
	}

	// Saved before the certificate: on a failure the name can still be unregistered.
	set := map[string]string{KEY_TOKEN: newToken}
	if email != "" {
		set[KEY_LE_EMAIL] = email
	}
	if err := calaos.UpdateConfig(set, nil); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("saving token: %v", err))
	}

	if token == "" || st.Domain != mainDomain || st.RegisteredAt == "" {
		st.RegisteredAt = nowString()
	}
	st.Domain = mainDomain
	st.Subdomains = subs

	if email == "" {
		if email, cerr = a.getConfig(KEY_LE_EMAIL); cerr != nil {
			return cerr
		}
	}
	if email == "" && !a.json {
		email = a.promptEmail()
	}
	st.EmailSet = email != ""
	if cerr := a.saveState(st); cerr != nil {
		return cerr
	}
	if email == "" {
		return localErr(codeNoEmail, errors.New("the name is registered, but no certificate was requested"))
	}

	if cerr := a.issue(&st, email, newToken); cerr != nil {
		return cerr
	}
	if cerr := installCert(haconf); cerr != nil {
		return cerr
	}

	a.success("Register successful.")
	return nil
}

func (a *app) promptEmail() string {
	a.say("%s To generate a Let's Encrypt certificate, you need to set a user email address.", CharWarning)
	fmt.Fprint(a.out, "Enter your email address: ")
	email := a.readLine(254)
	if !validEmail(email) {
		a.say("This email address is not valid. No certificate will be generated.")
		return ""
	}
	a.addSecret(email)
	if err := calaos.SetConfig(KEY_LE_EMAIL, email); err != nil {
		a.say("Failed to save le_email: %v", err)
	}
	return email
}

func (a *app) cmdChange(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS] NEWDOMAIN [OPTIONS]"
	var (
		email     = cmd.StringOpt("email", "", "Let's Encrypt e-mail address (default: the stored one)")
		_         = cmd.BoolOpt("json", false, jsonHelp)
		newDomain = cmd.StringArg("NEWDOMAIN", "", "The new name (ex. newname for newname.calaos.fr)")
	)

	cmd.Action = a.locked(func() *cmdError {
		return a.change(*newDomain, *email)
	})
}

// change registers the new name first and drops the old one only once the
// new one has a certificate and its token is stored: any earlier failure
// leaves the current registration as it was.
func (a *app) change(newDomain, email string) *cmdError {
	if !nameRe.MatchString(newDomain) {
		return localErr(codeInvalidName, errors.New("invalid name"))
	}
	if email != "" && !validEmail(email) {
		return localErr(codeNoEmail, errors.New("invalid e-mail address"))
	}
	a.addSecret(email)

	oldToken, cerr := a.getConfig(KEY_TOKEN)
	if cerr != nil {
		return cerr
	}
	if oldToken == "" {
		return localErr(codeUnknownToken, errors.New("no registration to change"))
	}
	storedEmail, cerr := a.getConfig(KEY_LE_EMAIL)
	if cerr != nil {
		return cerr
	}
	if email == "" {
		email = storedEmail
	}
	if email == "" {
		return localErr(codeNoEmail, nil)
	}

	st := loadOrInferState()
	haconf, err := haproxy.ParseDomains(newDomain, st.subdomainArgs())
	if err != nil {
		return localErr(codeInvalidName, err)
	}
	a.result["domain"] = newDomain

	newToken, cerr := a.backendRegister(newDomain, subdomainNames(st.Subdomains), "")
	if cerr != nil {
		return cerr
	}

	restore := snapshotCache()
	rollback := func() {
		restore()
		if derr := a.backendDelete(newToken); derr != nil {
			log.Println("change: failed to delete the new name after a failure:", a.scrub(derr.Error()))
		}
	}

	next := st
	next.Domain = newDomain
	next.Subdomains = subdomainsOf(haconf)
	err = a.withSpinner("Getting a certificate from Let's Encrypt. Please wait...", func() error {
		return issueCert(next.certDomains(), email, newToken)
	})
	if cerr := certError(err); cerr != nil {
		rollback()
		return cerr
	}

	set := map[string]string{KEY_TOKEN: newToken}
	if email != storedEmail {
		set[KEY_LE_EMAIL] = email
	}
	if err := calaos.UpdateConfig(set, nil); err != nil {
		rollback()
		return localErr(codeConfigWrite, fmt.Errorf("saving token: %v", err))
	}

	next.RegisteredAt = nowString()
	next.EmailSet = true
	next.LastCert = &CertResult{At: nowString(), OK: true, Renewed: true}
	stateErr := a.saveState(next)

	if derr := a.backendDelete(oldToken); derr != nil {
		// The old name is no longer updated: the backend drops it after 10 days.
		a.say("%s The old name could not be deleted: %v", CharWarning, derr)
		a.result["old_deleted"] = false
	} else {
		a.result["old_deleted"] = true
	}

	if cerr := installCert(haconf); cerr != nil {
		return cerr
	}
	if stateErr != nil {
		return stateErr
	}

	a.success("Change successful.")
	return nil
}

func (a *app) cmdUnregister(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS]"
	var (
		local = cmd.BoolOpt("local", false, "Only forget the local token, without calling the DNS server")
		_     = cmd.BoolOpt("json", false, jsonHelp)
	)

	cmd.Action = a.locked(func() *cmdError {
		if *local {
			return a.forget("Reset successful.")
		}
		return a.unregister()
	})
}

func (a *app) cmdReset(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS]"
	cmd.BoolOpt("json", false, jsonHelp)
	cmd.Action = a.locked(func() *cmdError {
		return a.forget("Reset successful.")
	})
}

func (a *app) unregister() *cmdError {
	token, cerr := a.getConfig(KEY_TOKEN)
	if cerr != nil {
		return cerr
	}
	if token == "" {
		return localErr(codeUnknownToken, errors.New("saved token not found, nothing to unregister"))
	}

	if cerr := a.backendDelete(token); cerr != nil {
		return cerr
	}

	return a.forget("Unregister successful.")
}

// forget drops the token and the registration from the state. The
// certificate cache and haproxy.cfg are left in place.
func (a *app) forget(msg string) *cmdError {
	if err := calaos.DeleteConfig(KEY_TOKEN); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("deleting token from config: %v", err))
	}

	email, cerr := a.getConfig(KEY_LE_EMAIL)
	if cerr != nil {
		return cerr
	}
	old, _ := loadState()
	if cerr := a.saveState(State{EmailSet: email != "", LastUpdate: old.LastUpdate, LastCert: old.LastCert}); cerr != nil {
		return cerr
	}

	a.success(msg)
	return nil
}

func (a *app) cmdUpdate(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS]"
	var (
		forceRenew = cmd.BoolOpt("f force-renew", false, "Force renew even if certificate is not expired")
		_          = cmd.BoolOpt("json", false, jsonHelp)
	)

	cmd.Action = a.locked(func() *cmdError {
		return a.update(*forceRenew)
	})
}

func (a *app) update(forceRenew bool) *cmdError {
	token, cerr := a.getConfig(KEY_TOKEN)
	if cerr != nil {
		return cerr
	}
	if token == "" {
		a.result["updated"] = false
		a.say("No DDNS registration found. Nothing to update.")
		return nil
	}

	st := loadOrInferState()

	log.Println("Updating IP address")
	cerr = a.backendUpdate(token)
	st.LastUpdate = &RunResult{At: nowString(), OK: cerr == nil, Code: errCode(cerr)}
	if serr := a.saveState(st); serr != nil && cerr == nil {
		return serr
	}
	if cerr != nil {
		return cerr
	}
	a.result["updated"] = true

	email, cerr := a.getConfig(KEY_LE_EMAIL)
	if cerr != nil {
		return cerr
	}

	renewed := false
	if !certIsCached() {
		// Repair after a restore on a new box: the cache is gone, the
		// registration is not.
		if st.Domain == "" {
			cerr = newErr(codeAcmeFailed, errors.New("no certificate in cache and no known domain"))
			st.LastCert = &CertResult{At: nowString(), OK: false, Code: cerr.code}
			a.saveState(st)
			return cerr
		}
		if email == "" {
			return localErr(codeNoEmail, errors.New("no certificate in cache"))
		}
		if cerr := a.issue(&st, email, token); cerr != nil {
			return cerr
		}
		renewed = true
	} else {
		var err error
		werr := a.withSpinner("Renewing certificate. Please wait...", func() error {
			renewed, err = renewCert(forceRenew, email, token)
			return err
		})
		if cerr := certError(werr); cerr != nil {
			st.LastCert = &CertResult{At: nowString(), OK: false, Code: cerr.code}
			a.saveState(st)
			return cerr
		}
		if renewed {
			st.LastCert = &CertResult{At: nowString(), OK: true, Renewed: true}
			if cerr := a.saveState(st); cerr != nil {
				return cerr
			}
		}
	}
	a.result["renewed"] = renewed

	if !renewed {
		a.success("Update successful.")
		return nil
	}

	//Copy the certificate to haproxy location and concatenate key+cert
	if err := lecert.WritePemFile(certFile()); err != nil {
		return localErr(codeConfigWrite, fmt.Errorf("writing certificate: %v", err))
	}
	if err := restartHaproxy(); err != nil {
		return localErr(codeInternal, fmt.Errorf("restarting haproxy: %v", err))
	}

	a.success("Update successful. Certificate has been renewed")
	return nil
}
