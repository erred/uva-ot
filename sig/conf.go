package sig

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/ebfe/signify"
	"sigs.k8s.io/yaml"
)

type Config struct {
	Keys      []Key `json:"keys"`
	sha256key map[[32]byte][]*signify.PublicKey
}

type Key struct {
	Pubkey     string        `json:"pubkeys"`
	Sha256Sums []AllowedItem `json:"sha256sums,omitempty"`
}

type AllowedItem struct {
	Hash string `json:"hash"`
}

// NewConfig parses a config from a file
func NewConfig(fpath string) (*Config, error) {
	b, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fpath, err)
	}
	c := &Config{
		sha256key: make(map[[32]byte][]*signify.PublicKey),
	}
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", fpath, err)
	}
	for i, key := range c.Keys {
		pkb, err := base64.StdEncoding.DecodeString(key.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey %d %s: %w", i, key.Pubkey, err)
		}
		pk, err := signify.ParsePublicKey(pkb)
		if err != nil {
			return nil, fmt.Errorf("parse pubkey %d %s: %w", i, key.Pubkey, err)
		}

		for j, ai := range key.Sha256Sums {
			b, err := base64.StdEncoding.DecodeString(ai.Hash)
			if err != nil {
				return nil, fmt.Errorf("parse hash %d:%d %s: %w", i, j, ai.Hash, err)
			} else if len(b) != 32 {
				return nil, fmt.Errorf("parse hash %d:%d %s: expected 32 bytes got %d",
					i, j, ai.Hash, len(b))
			}

			var hash [32]byte
			copy(hash[:], b)
			c.sha256key[hash] = append(c.sha256key[hash], pk)
		}
	}
	return c, nil
}
