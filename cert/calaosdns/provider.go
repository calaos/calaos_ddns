package calaosdns

//implement a DNS provider for solving DNS-01 challenges using Calaos DNS

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dghubble/sling"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/dns01"
	"github.com/xenolf/lego/platform/config/env"
)

// BaseURL is the Calaos DNS API (overridden by tests).
var BaseURL = "https://ns1.calaos.fr/"

// Config is used to configure the creation of the DNSProvider
type Config struct {
	APIKey             string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond("CALAOSDNS_PROPAGATION_TIMEOUT", 120*time.Second),
		PollingInterval:    env.GetOrDefaultSecond("CALAOSDNS_POLLING_INTERVAL", 2*time.Second),
	}
}

// DNSProvider describes a provider for calaos-proxy
type DNSProvider struct {
	config *Config
}

// NewDNSProvider takes the token explicitly: during a name change the new
// token is not stored in local_config.xml yet.
func NewDNSProvider(token string) (challenge.Provider, error) {
	config := NewDefaultConfig()
	config.APIKey = token

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for pdns.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("calaosdns: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("calaosdns: API key missing")
	}

	d := &DNSProvider{config: config}
	return d, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

type LeJson struct {
	Token    string `json:"token" form:"token" query:"token"`
	LeDomain string `json:"le_domain" form:"le_domain" query:"le_domain"`
	LeToken  string `json:"le_token" form:"le_token" query:"le_token"`
}

// Present creates a TXT record to fulfill the dns-01 challenge
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	_, value := dns01.GetRecord(domain, keyAuth)

	subdomain := domain
	if i := strings.IndexByte(subdomain, '.'); i >= 0 {
		subdomain = subdomain[:i]
	}

	jdata := LeJson{
		Token:    d.config.APIKey,
		LeDomain: subdomain,
		LeToken:  value,
	}

	slingReq, err := sling.New().Base(BaseURL).Post("api/letsencrypt").BodyJSON(jdata).Request()
	if err != nil {
		return fmt.Errorf("calaosdns: Error creating sling: %v", err)
	}

	_, err = doRequest(slingReq)
	if err != nil {
		log.Printf("calaosdns: Error doing request for %v: %v", jdata.LeDomain, err)
		return fmt.Errorf("calaosdns: Error doing request")
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	subdomain := domain
	if i := strings.IndexByte(subdomain, '.'); i >= 0 {
		subdomain = subdomain[:i]
	}

	jdata := LeJson{
		Token:    d.config.APIKey,
		LeDomain: subdomain,
	}

	slingReq, err := sling.New().Base(BaseURL).Delete("api/letsencrypt").BodyJSON(jdata).Request()
	if err != nil {
		return fmt.Errorf("calaosdns: Error creating sling: %v", err)
	}

	_, err = doRequest(slingReq)
	if err != nil {
		log.Printf("calaosdns: Error doing request for %v: %v", jdata.LeDomain, err)
		return fmt.Errorf("calaosdns: Error doing request")
	}

	return nil
}

func doRequest(req *http.Request) (data []byte, err error) {
	failJson := &struct {
		Message string `json:"message"`
	}{Message: ""}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			err = ue.Err
		}
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		json.NewDecoder(resp.Body).Decode(&failJson)
		return nil, fmt.Errorf("Error: %v", failJson.Message)
	}
	return ioutil.ReadAll(resp.Body)
}
