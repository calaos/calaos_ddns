package calaos

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const tricky = `a&b"c<d>e'f` + "\tg\nh"

func setup(t *testing.T, content string) string {
	t.Helper()
	configBase = t.TempDir()
	t.Cleanup(func() { configBase = "" })

	p := filepath.Join(configBase, LOCAL_CONFIG)
	if content != "" {
		if err := os.WriteFile(p, []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

const sample = `<?xml version="1.0" encoding="UTF-8"?>
<calaos:config xmlns:calaos="http://www.calaos.fr">
    <calaos:option name="smtp_password" value="p&amp;ss&quot;w&lt;rd&gt;" />
    <calaos:option name="cn_user" value="me" />
    <calaos:option name="flag" />
</calaos:config>
`

func get(t *testing.T, key string) string {
	t.Helper()
	err, v := GetConfig(key)
	if err != nil {
		t.Fatalf("GetConfig(%s): %v", key, err)
	}
	return v
}

func TestGetConfigMissingFile(t *testing.T) {
	setup(t, "")

	err, v := GetConfig("ddns_token")
	if err != nil || v != "" {
		t.Fatalf("want (nil, \"\"), got (%v, %q)", err, v)
	}
}

func TestGetConfigValue(t *testing.T) {
	setup(t, `<?xml version="1.0"?><calaos:config xmlns:calaos="http://www.calaos.fr"><calaos:option name="ddns_token" value="abc"/></calaos:config>`)

	if v := get(t, "ddns_token"); v != "abc" {
		t.Fatalf("got %q", v)
	}
}

func TestSetConfigEscapesAndKeepsOtherOptions(t *testing.T) {
	p := setup(t, sample)

	if err := SetConfig("ddns_le_email", tricky); err != nil {
		t.Fatal(err)
	}
	if err := SetConfig("cn_user", tricky); err != nil {
		t.Fatal(err)
	}

	if v := get(t, "smtp_password"); v != `p&ss"w<rd>` {
		t.Fatalf("smtp_password altered: %q", v)
	}
	if v := get(t, "ddns_le_email"); v != tricky {
		t.Fatalf("ddns_le_email: %q", v)
	}
	if v := get(t, "cn_user"); v != tricky {
		t.Fatalf("cn_user: %q", v)
	}

	b, _ := os.ReadFile(p)
	s := string(b)
	if strings.Index(s, "smtp_password") > strings.Index(s, "cn_user") ||
		strings.Index(s, "cn_user") > strings.Index(s, "ddns_le_email") {
		t.Fatalf("option order not kept:\n%s", s)
	}
	if !strings.Contains(s, `<calaos:option name="flag" />`) {
		t.Fatalf("option without value not kept:\n%s", s)
	}
	if _, err := parseOptions(b); err != nil {
		t.Fatalf("written file does not parse: %v\n%s", err, s)
	}
}

func TestKeyWithSpecialCharacters(t *testing.T) {
	setup(t, sample)
	if err := SetConfig(`k&"<>`, `v&"<>`); err != nil {
		t.Fatal(err)
	}
	if v := get(t, `k&"<>`); v != `v&"<>` {
		t.Fatalf("got %q", v)
	}
}

func TestDeleteConfig(t *testing.T) {
	setup(t, sample)
	if err := SetConfig("ddns_token", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteConfig("ddns_token"); err != nil {
		t.Fatal(err)
	}
	if v := get(t, "ddns_token"); v != "" {
		t.Fatalf("token still there: %q", v)
	}
	if v := get(t, "smtp_password"); v != `p&ss"w<rd>` {
		t.Fatalf("smtp_password altered: %q", v)
	}
}

func TestDeleteConfigMissingFile(t *testing.T) {
	p := setup(t, "")
	if err := DeleteConfig("ddns_token"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("DeleteConfig created the file")
	}
}

func TestSetConfigMissingFileFails(t *testing.T) {
	setup(t, "")
	if err := SetConfig("ddns_token", "x"); err == nil {
		t.Fatal("want an error")
	}
}

func TestRefusesUnparseableFile(t *testing.T) {
	for name, content := range map[string]string{
		"truncated":  `<?xml version="1.0"?><calaos:config xmlns:calaos="http://www.calaos.fr"><calaos:option name="smtp_password" value="x"`,
		"raw amp":    `<calaos:config><calaos:option name="smtp_password" value="a&b" /></calaos:config>`,
		"empty":      " ",
		"other node": `<calaos:config><calaos:option name="a" value="b" /><other/></calaos:config>`,
		"text":       `<calaos:config>text<calaos:option name="a" value="b" /></calaos:config>`,
	} {
		t.Run(name, func(t *testing.T) {
			p := setup(t, content)

			err := SetConfig("ddns_token", "0123456789abcdef")
			if !errors.Is(err, ErrUnparseable) {
				t.Fatalf("want ErrUnparseable, got %v", err)
			}
			if err := DeleteConfig("smtp_password"); !errors.Is(err, ErrUnparseable) {
				t.Fatalf("delete: want ErrUnparseable, got %v", err)
			}
			b, _ := os.ReadFile(p)
			if string(b) != content {
				t.Fatalf("file was modified: %q", b)
			}
			if err, _ := GetConfig("smtp_password"); err == nil {
				t.Fatal("GetConfig must report the parse error")
			}
		})
	}
}

func TestWriteKeepsModeAndSymlink(t *testing.T) {
	setup(t, "")
	real := filepath.Join(t.TempDir(), "real.xml")
	if err := os.WriteFile(real, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(configBase, LOCAL_CONFIG)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := SetConfig("ddns_token", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", fi.Mode(), err)
	}
	fi, _ = os.Stat(real)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode changed: %v", fi.Mode())
	}
	if v := get(t, "ddns_token"); v != "0123456789abcdef" {
		t.Fatalf("got %q", v)
	}

	entries, _ := os.ReadDir(filepath.Dir(real))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
	lf, err := os.Stat(link + ".lock")
	if err != nil || lf.Mode().Perm() != 0600 {
		t.Fatalf("lock file: %v %v", lf, err)
	}
}

func TestConcurrentWritersLoseNoKey(t *testing.T) {
	setup(t, sample)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := SetConfig(fmt.Sprintf("key%d", i), fmt.Sprintf(`v&"<>%d`, i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < 20; i++ {
		if v := get(t, fmt.Sprintf("key%d", i)); v != fmt.Sprintf(`v&"<>%d`, i) {
			t.Fatalf("key%d lost: %q", i, v)
		}
	}
	if v := get(t, "smtp_password"); v != `p&ss"w<rd>` {
		t.Fatalf("smtp_password altered: %q", v)
	}
}

func TestWriterWaitsForTheLock(t *testing.T) {
	setup(t, sample)

	unlock, err := lockConfig()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- SetConfig("ddns_token", "0123456789abcdef") }()

	select {
	case <-done:
		t.Fatal("SetConfig did not wait for the lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
