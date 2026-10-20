package calaos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetConfigMissingFile(t *testing.T) {
	configBase = t.TempDir()
	defer func() { configBase = "" }()

	err, v := GetConfig("ddns_token")
	if err != nil || v != "" {
		t.Fatalf("want (nil, \"\"), got (%v, %q)", err, v)
	}
}

func TestGetConfigValue(t *testing.T) {
	configBase = t.TempDir()
	defer func() { configBase = "" }()

	xml := `<?xml version="1.0"?><calaos:config xmlns:calaos="http://www.calaos.fr"><calaos:option name="ddns_token" value="abc"/></calaos:config>`
	if err := os.WriteFile(filepath.Join(configBase, LOCAL_CONFIG), []byte(xml), 0644); err != nil {
		t.Fatal(err)
	}

	err, v := GetConfig("ddns_token")
	if err != nil || v != "abc" {
		t.Fatalf("got (%v, %q)", err, v)
	}
}
