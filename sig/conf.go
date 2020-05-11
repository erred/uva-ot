package sig

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"go.seankhliao.com/signify"
	"sigs.k8s.io/yaml"
)

type Config struct {
	Keys      map[string][]string `json:"keys"`
	sha256key map[[32]byte][]*signify.PublicKey
	allowAll  map[signify.PublicKey]struct{}
}

// NewConfig parses a config from raw bytes
func NewConfig(b []byte) (*Config, error) {
	c := &Config{
		allowAll:  make(map[signify.PublicKey]struct{}),
		sha256key: make(map[[32]byte][]*signify.PublicKey),
	}
	err := yaml.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	for pubkey, hashes := range c.Keys {
		pkb, err := base64.StdEncoding.DecodeString(pubkey)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey %s: %w", pubkey, err)
		}
		pk, err := signify.ParsePublicKey(pkb)
		if err != nil {
			return nil, fmt.Errorf("parse pubkey %s: %w", pubkey, err)
		}

		for i, h := range hashes {
			if h == "*" {
				c.allowAll[*pk] = struct{}{}
				continue
			}

			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("parse hash %s: %d %s: %w", pubkey, i, h, err)
			} else if len(b) != 32 {
				return nil, fmt.Errorf("parse hash %s: %d %s: expected 32 bytes got %d",
					pubkey, i, h, len(b))
			}

			var hash [32]byte
			copy(hash[:], b)
			c.sha256key[hash] = append(c.sha256key[hash], pk)
		}
	}
	return c, nil
}

// NewConfigFromFile parses a config from a file on disk
func NewConfigFromFile(fpath string) (*Config, error) {
	b, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	return NewConfig(b)
}
