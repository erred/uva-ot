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
	Keys      []Key `json:"keys"`
	sha256key map[[32]byte][]*signify.PublicKey
	allowAll  map[signify.PublicKey]struct{}
}

type Key struct {
	Pubkey   string        `json:"pubkey"`
	AllowAll bool          `json:"allowAll"`
	Sha256   []AllowedItem `json:"sha256,omitempty"`
}

type AllowedItem struct {
	Hash string `json:"hash"`
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
	for i, key := range c.Keys {
		pkb, err := base64.StdEncoding.DecodeString(key.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey %d %s: %w", i, key.Pubkey, err)
		}
		pk, err := signify.ParsePublicKey(pkb)
		if err != nil {
			return nil, fmt.Errorf("parse pubkey %d %s: %w", i, key.Pubkey, err)
		}

		if key.AllowAll {
			c.allowAll[*pk] = struct{}{}
		}

		for j, ai := range key.Sha256 {
			b, err := hex.DecodeString(ai.Hash)
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

// NewConfigFromFile parses a config from a file on disk
func NewConfigFromFile(fpath string) (*Config, error) {
	b, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	return NewConfig(b)
}
