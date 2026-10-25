package calaos

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/mitchellh/go-homedir"
	"github.com/xenolf/lego/platform/config/env"
)

var (
	// configBase overrides CALAOS_CONFIG and the default lookup (tests).
	configBase string

	ErrUnparseable = errors.New("local_config.xml cannot be parsed")
)

const (
	LOCAL_CONFIG     = "local_config.xml"
	HOME_CONFIG_PATH = ".config/calaos"
	ETC_CONFIG_PATH  = "/etc/calaos"
)

func getDefaultConfig() (d string) {
	home, _ := homedir.Dir()
	confDirs := []string{
		home + "/" + HOME_CONFIG_PATH,
		ETC_CONFIG_PATH,
	}

	for _, d = range confDirs {
		conf := d + "/" + LOCAL_CONFIG
		if _, err := os.Stat(conf); !os.IsNotExist(err) {
			return
		}
	}

	log.Println("ERROR: Config file not found in any known dir!")

	return
}

func getConfigFile(file string) string {
	base := configBase
	if base == "" {
		base = env.GetOrDefaultString("CALAOS_CONFIG", getDefaultConfig())
	}

	return base + "/" + file
}

type CalaosOption struct {
	Key      string
	Value    string
	HasValue bool
}

// parseOptions refuses anything but calaos:option elements under the root, so
// that a rewrite can never silently drop content it did not understand.
func parseOptions(data []byte) ([]CalaosOption, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var opts []CalaosOption
	depth := 0
	seenRoot := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnparseable, err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case depth == 0 && !seenRoot && t.Name.Local == "config":
				seenRoot = true
			case depth == 1 && t.Name.Local == "option":
				opt := CalaosOption{}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "name":
						opt.Key = a.Value
					case "value":
						opt.Value = a.Value
						opt.HasValue = true
					}
				}
				opts = append(opts, opt)
			default:
				return nil, fmt.Errorf("%w: unexpected element <%s>", ErrUnparseable, t.Name.Local)
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return nil, fmt.Errorf("%w: unexpected text", ErrUnparseable)
			}
		}
	}

	if !seenRoot || depth != 0 {
		return nil, fmt.Errorf("%w: no calaos:config root", ErrUnparseable)
	}

	return opts, nil
}

func escapeAttr(s string) string {
	var b bytes.Buffer
	// EscapeText also escapes \t \n \r, which attribute normalization would
	// otherwise turn into spaces on the next read.
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func serializeOptions(opts []CalaosOption) []byte {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<calaos:config xmlns:calaos=\"http://www.calaos.fr\">\n")
	for _, o := range opts {
		b.WriteString("    <calaos:option name=\"" + escapeAttr(o.Key) + "\"")
		if o.HasValue {
			b.WriteString(" value=\"" + escapeAttr(o.Value) + "\"")
		}
		b.WriteString(" />\n")
	}
	b.WriteString("</calaos:config>\n")
	return b.Bytes()
}

// The lock is on a companion file, as calaos_server does: the rename below
// replaces the inode of local_config.xml, a lock on it would be dropped.
func lockConfig() (unlock func(), err error) {
	f, err := os.OpenFile(getConfigFile(LOCAL_CONFIG)+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}

	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}

	return func() { f.Close() }, nil
}

// writeAtomic replaces path without ever leaving a partial file, keeping the
// mode and owner of the original (it holds smtp_password and other secrets).
func writeAtomic(path string, data []byte) (err error) {
	// local_config.xml may be a symlink to persistent storage: renaming onto
	// the link would replace it by a regular file.
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(target)
	if err != nil {
		return err
	}

	dir := filepath.Dir(target)
	tmp, err := ioutil.TempFile(dir, "."+filepath.Base(target)+".")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) != os.Geteuid() || int(sys.Gid) != os.Getegid()) {
		if cerr := tmp.Chown(int(sys.Uid), int(sys.Gid)); cerr != nil {
			log.Println("Unable to preserve owner of", target, ":", cerr)
		}
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
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}

	if d, derr := os.Open(dir); derr == nil {
		d.Sync()
		d.Close()
	}

	return nil
}

func readOptions() ([]CalaosOption, error) {
	data, err := ioutil.ReadFile(getConfigFile(LOCAL_CONFIG))
	if err != nil {
		return nil, err
	}
	return parseOptions(data)
}

// GetConfig needs no lock: every writer renames a complete file into place.
func GetConfig(key string) (err error, value string) {
	opts, err := readOptions()
	if err != nil {
		// calaos-server creates the file on its first start; until then nothing is configured.
		if os.IsNotExist(err) {
			return nil, ""
		}
		log.Println("Failed to read config:", err)
		return
	}

	for _, opt := range opts {
		if opt.Key == key && opt.HasValue {
			return nil, opt.Value
		}
	}

	return
}

// UpdateConfig sets and deletes keys in one locked read-modify-write. It
// refuses to write when the current file cannot be parsed.
func UpdateConfig(set map[string]string, del []string) error {
	unlock, err := lockConfig()
	if err != nil {
		return err
	}
	defer unlock()

	opts, err := readOptions()
	if err != nil {
		return err
	}

	isDeleted := func(k string) bool {
		for _, d := range del {
			if d == k {
				return true
			}
		}
		return false
	}

	done := map[string]bool{}
	out := make([]CalaosOption, 0, len(opts)+len(set))
	for _, o := range opts {
		if isDeleted(o.Key) {
			continue
		}
		if v, ok := set[o.Key]; ok {
			o.Value = v
			o.HasValue = true
			done[o.Key] = true
		}
		out = append(out, o)
	}
	for _, k := range sortedKeys(set) {
		if !done[k] {
			out = append(out, CalaosOption{Key: k, Value: set[k], HasValue: true})
		}
	}

	return writeAtomic(getConfigFile(LOCAL_CONFIG), serializeOptions(out))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SetConfig(key, value string) error {
	return UpdateConfig(map[string]string{key: value}, nil)
}

func DeleteConfig(key string) error {
	err := UpdateConfig(nil, []string{key})
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
