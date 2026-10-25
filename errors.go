package main

import (
	"errors"
	"strings"

	lecert "github.com/calaos/calaos_ddns/cert"
)

// Error codes of the --json output. The daemon relays them to the webapp.
const (
	codeHostTaken          = "host_taken"
	codeWrongToken         = "wrong_token"
	codeUnknownToken       = "unknown_token"
	codeInvalidName        = "invalid_name"
	codeBackendUnreachable = "backend_unreachable"
	codeAcmeFailed         = "acme_failed"
	codeDNSPropagation     = "dns_propagation"
	codeNoEmail            = "no_email"
	codeConfigWrite        = "config_write"
	codeBusy               = "busy"
	codeInternal           = "internal"
)

// Exit codes.
const (
	exitOK          = 0
	exitLocal       = 1
	exitRefused     = 2
	exitUnreachable = 3
	exitCert        = 4
	exitBusy        = 5
)

type codeInfo struct {
	exit int
	msg  string
}

// msg is a fixed text: it goes into the JSON output, so it must never carry
// a value read at run time (the token in particular).
var codes = map[string]codeInfo{
	codeHostTaken:          {exitRefused, "This name is already registered"},
	codeWrongToken:         {exitRefused, "The token does not match this name"},
	codeUnknownToken:       {exitRefused, "The registration token is unknown"},
	codeInvalidName:        {exitRefused, "The name is not valid"},
	codeBackendUnreachable: {exitUnreachable, "The Calaos DNS server cannot be reached"},
	codeAcmeFailed:         {exitCert, "The certificate could not be obtained"},
	codeDNSPropagation:     {exitCert, "The DNS challenge did not propagate in time"},
	codeNoEmail:            {exitLocal, "An e-mail address is needed for the certificate"},
	codeConfigWrite:        {exitLocal, "The local configuration could not be written"},
	codeBusy:               {exitBusy, "Another calaos_ddns run is in progress"},
	codeInternal:           {exitLocal, "Internal error"},
}

type cmdError struct {
	code   string
	exit   int
	detail error
}

func (e *cmdError) Error() string {
	if e.detail == nil {
		return codes[e.code].msg
	}
	return codes[e.code].msg + ": " + e.detail.Error()
}

// newErr uses the exit code of the code's origin (backend, ACME...).
func newErr(code string, detail error) *cmdError {
	return &cmdError{code: code, exit: codes[code].exit, detail: detail}
}

// localErr is a refusal decided locally (validation, missing token): exit 1.
func localErr(code string, detail error) *cmdError {
	return &cmdError{code: code, exit: exitLocal, detail: detail}
}

func errCode(e *cmdError) string {
	if e == nil {
		return ""
	}
	return e.code
}

// backendMessages maps the fixed messages of calaos_dns to error codes.
var backendMessages = map[string]string{
	"Host already registered": codeHostTaken,
	"Wrong token":             codeWrongToken,
	"Unknown token":           codeUnknownToken,
	"Invalid hostname":        codeInvalidName,
	"Mainzone is empty":       codeInvalidName,
}

func certError(err error) *cmdError {
	if err == nil {
		return nil
	}
	if errors.Is(err, lecert.ErrNoEmail) {
		return localErr(codeNoEmail, err)
	}
	// lego's wait.For error when the TXT record is not visible in time.
	if strings.Contains(err.Error(), "time limit exceeded") {
		return newErr(codeDNSPropagation, err)
	}
	return newErr(codeAcmeFailed, err)
}
