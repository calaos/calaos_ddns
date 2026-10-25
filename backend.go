package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/dghubble/sling"
)

// nsURL is the Calaos DNS API (overridden by tests).
var nsURL = "https://ns1.calaos.fr/"

type RegisterJson struct {
	Mainzone string `json:"mainzone"`
	Subzones string `json:"subzones"`
	Token    string `json:"token"`
}

func (a *app) backendRegister(mainzone string, subzones []string, token string) (string, *cmdError) {
	jdata := RegisterJson{
		Mainzone: mainzone,
		Subzones: strings.Join(subzones, ","),
		Token:    token,
	}

	req, err := sling.New().Base(nsURL).Post("api/register").BodyJSON(jdata).Request()
	if err != nil {
		return "", localErr(codeInternal, err)
	}

	data, cerr := a.doRequest(req)
	if cerr != nil {
		return "", cerr
	}

	r := RegisterJson{}
	if err := json.Unmarshal(data, &r); err != nil || !validToken(r.Token) {
		return "", newErr(codeBackendUnreachable, errors.New("unexpected answer to register"))
	}
	a.addSecret(r.Token)

	return r.Token, nil
}

func (a *app) backendUpdate(token string) *cmdError {
	req, err := sling.New().Base(nsURL).Get("api/update/" + url.PathEscape(token)).Request()
	if err != nil {
		return localErr(codeInternal, errors.New("cannot build the update request"))
	}
	_, cerr := a.doRequest(req)
	return cerr
}

func (a *app) backendDelete(token string) *cmdError {
	req, err := sling.New().Base(nsURL).Delete("api/delete/" + url.PathEscape(token)).Request()
	if err != nil {
		return localErr(codeInternal, errors.New("cannot build the delete request"))
	}
	_, cerr := a.doRequest(req)
	return cerr
}

func (a *app) doRequest(req *http.Request) ([]byte, *cmdError) {
	if a.interactive() {
		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		s.Suffix = "  please wait..."
		s.Color("blue")
		s.Start()
		defer s.Stop()
	}

	return doRequestReal(req)
}

// Errors returned here never carry the request URL: the token is in its path.
func doRequestReal(req *http.Request) ([]byte, *cmdError) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			err = ue.Err
		}
		return nil, newErr(codeBackendUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return nil, newErr(codeBackendUnreachable, fmt.Errorf("HTTP %d", resp.StatusCode))
	}

	if resp.StatusCode >= 400 {
		failJson := struct {
			Message string `json:"message"`
		}{}
		if json.NewDecoder(resp.Body).Decode(&failJson) != nil {
			return nil, newErr(codeBackendUnreachable, fmt.Errorf("HTTP %d", resp.StatusCode))
		}
		if code, ok := backendMessages[failJson.Message]; ok {
			return nil, newErr(code, errors.New(failJson.Message))
		}
		return nil, &cmdError{code: codeInternal, exit: exitRefused, detail: fmt.Errorf("HTTP %d: %s", resp.StatusCode, failJson.Message)}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, newErr(codeBackendUnreachable, err)
	}
	return data, nil
}
