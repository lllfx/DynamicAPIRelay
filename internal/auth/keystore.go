// Package auth verifies relay keys in constant time.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
)

type entry struct {
	id   string
	hash [sha256.Size]byte
}

// KeyStore holds hashes of the configured relay secrets.
type KeyStore struct {
	entries []entry
}

// NewKeyStore builds a store from keyID -> secret; only hashes are retained.
func NewKeyStore(keys map[string]string) *KeyStore {
	s := &KeyStore{}
	for id, secret := range keys {
		s.entries = append(s.entries, entry{id: id, hash: sha256.Sum256([]byte(secret))})
	}
	return s
}

// Authenticate returns the key ID matching presented. Every stored hash is
// compared so timing does not depend on which key (if any) matches.
func (s *KeyStore) Authenticate(presented string) (keyID string, ok bool) {
	if presented == "" {
		return "", false
	}
	h := sha256.Sum256([]byte(presented))
	for _, e := range s.entries {
		if subtle.ConstantTimeCompare(h[:], e.hash[:]) == 1 {
			keyID, ok = e.id, true
		}
	}
	return keyID, ok
}
