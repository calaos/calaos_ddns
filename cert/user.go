package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/xenolf/lego/registration"
)

// SSLUser implements the ACME User interface
type SSLUser struct {
	Email        string
	Registration *registration.Resource
	Key          *rsa.PrivateKey
}

func (u SSLUser) GetEmail() string {
	return u.Email
}

func (u SSLUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u SSLUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// get SSL User from cacheDir or create a new one
func getUser(email string) (SSLUser, error) {
	var u SSLUser

	b, err := ioutil.ReadFile(conf.CacheDir + "/SSLUser.json")
	if err == nil {
		if err = json.Unmarshal(b, &u); err == nil && u.Key != nil {
			return u, nil
		}
		log.Println("cert: unusable SSLUser.json, creating a new ACME account:", err)
	}

	if email == "" {
		return u, ErrNoEmail
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return u, err
	}

	return SSLUser{
		Email: email,
		Key:   privateKey,
	}, nil
}

// save the user on disk
// fatals on error
func saveUserToDisk(u SSLUser, cacheDir string) {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		log.Println("[FATAL] cert: failed to marshal user: ", err)
	}
	err = ioutil.WriteFile(conf.CacheDir+"/SSLUser.json", b, conf.CacheDirPerm)
	if err != nil {
		log.Println("[FATAL] cert: failed to write user to disk: ", err)
	}
}
