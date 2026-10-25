package main

import (
	"time"

	cli "github.com/jawher/mow.cli"
	"github.com/miekg/dns"
)

// nsDNSAddr is asked directly, so that dns_ip is what the authoritative
// server publishes now, not a cached answer (overridden by tests).
var nsDNSAddr = "ns1.calaos.fr:53"

func lookupDNSIP(fqdn string) string {
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = false

	r, _, err := c.Exchange(m, nsDNSAddr)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func (a *app) cmdStatus(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS]"
	cmd.BoolOpt("json", false, jsonHelp)

	// No run lock and no log file: status runs while other commands do.
	cmd.Action = func() {
		a.ran = true
		a.err = a.status()
	}
}

func (a *app) status() *cmdError {
	token, cerr := a.getConfig(KEY_TOKEN)
	if cerr != nil {
		return cerr
	}
	email, cerr := a.getConfig(KEY_LE_EMAIL)
	if cerr != nil {
		return cerr
	}

	ci := readServedCert()
	st, found := loadState()
	if !found {
		st = inferState(ci)
	}
	if st.Subdomains == nil {
		st.Subdomains = []Subdomain{}
	}

	dnsIP := ""
	if st.Domain != "" {
		dnsIP = lookupDNSIP(st.Domain + ".calaos.fr")
	}

	r := a.result
	r["token_set"] = token != ""
	r["domain"] = st.Domain
	r["subdomains"] = st.Subdomains
	r["email_set"] = email != ""
	r["email"] = maskEmail(email)
	r["registered_at"] = st.RegisteredAt
	r["last_update"] = st.LastUpdate
	r["last_cert"] = st.LastCert
	r["dns_ip"] = dnsIP
	r["cert"] = ci

	if a.json {
		return nil
	}

	a.say("Token:        %v", yesNo(token != ""))
	if st.Domain != "" {
		a.say("Domain:       %s.calaos.fr", st.Domain)
	} else {
		a.say("Domain:       (unknown)")
	}
	for _, s := range st.Subdomains {
		a.say("Sub-domain:   %s.%s.calaos.fr", s.Name, st.Domain)
	}
	a.say("E-mail:       %s", maskEmail(email))
	a.say("DNS address:  %s", dnsIP)
	if st.LastUpdate != nil {
		a.say("Last update:  %s ok=%v %s", st.LastUpdate.At, st.LastUpdate.OK, st.LastUpdate.Code)
	}
	if ci != nil {
		a.say("Certificate:  %s, until %s, self-signed=%v", ci.Issuer, ci.NotAfter, ci.SelfSigned)
	}
	if st.LastCert != nil {
		a.say("Last cert:    %s ok=%v renewed=%v %s", st.LastCert.At, st.LastCert.OK, st.LastCert.Renewed, st.LastCert.Code)
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "set"
	}
	return "not set"
}
