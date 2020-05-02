package sig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestVerify(t *testing.T) {
	// privkey: RWRCSwAAAAB/LS7sgYhbtA0E8k4e7T0VJfod6GIOYxv1JFtHhbzLGcb9N5XaHxYOpw6DE2gikozUxjL/Z7MdM/5WBU0lRoH52Zya3AIL/axSMraYMq4eRy9LjJdsodkCEZ38O4Ys2qI=
	c, err := NewConfig([]byte(`
keys:
  - pubkey: RWT1JFtHhbzLGdmcmtwCC/2sUjK2mDKuHkcvS4yXbKHZAhGd/DuGLNqi
    sha256:
      - hash: dea6e6d7cbb0a0566113b1e748746005fa0ac540ec5c35d56ab52d06b56fd781
`))
	if err != nil {
		t.Errorf("TestVerify setup: parse config err: %v\n", err)
		t.FailNow()
	}
	tcs := []struct {
		in   []byte
		pass bool
	}{
		{
			[]byte(`#!/usr/bin/env bash
echo hello world

# :AUTHSIGv0:37:RWT1JFtHhbzLGXqMPIXetBWUKEKVaTSFyhLiCPJOsCscn5qWcpHey0Euj0Emi5H29QchhsxfyeQZBqLM2GA6YqlIJn/OpT1x5Ac=:`),
			true,
		},
	}
	for i, tc := range tcs {
		err := c.Verify(bytes.NewReader(tc.in))
		if (tc.pass && err != nil) || (!tc.pass && err == nil) {
			t.Errorf("TestVerify %d: should pass %v err: %v\n", i, tc.pass, err)
		}
	}

}

func TestRoundtrip(t *testing.T) {
	tcs := []struct {
		prefix string
		in     []byte
	}{
		{
			"",
			[]byte(`hello world`),
		},
	}

	signer, err := NewSigner("RWRCSwAAAAB/LS7sgYhbtA0E8k4e7T0VJfod6GIOYxv1JFtHhbzLGcb9N5XaHxYOpw6DE2gikozUxjL/Z7MdM/5WBU0lRoH52Zya3AIL/axSMraYMq4eRy9LjJdsodkCEZ38O4Ys2qI=", "")
	if err != nil {
		t.Errorf("TestRoundtrip signer: %v\n", err)
		t.FailNow()
	}

	key := Key{
		Pubkey: "RWT1JFtHhbzLGdmcmtwCC/2sUjK2mDKuHkcvS4yXbKHZAhGd/DuGLNqi",
	}
	for _, tc := range tcs {
		sumb := sha256.Sum256(tc.in)
		sum := hex.EncodeToString(sumb[:])
		key.Sha256 = append(key.Sha256, AllowedItem{Hash: sum})
	}
	b, err := yaml.Marshal(Config{Keys: []Key{key}})
	if err != nil {
		t.Errorf("TestRoundtrip marshal config: %v\n", err)
		t.FailNow()
	}
	c, err := NewConfig(b)
	if err != nil {
		t.Errorf("TestRoundtrip NewConfig: %v\n", err)
		t.FailNow()
	}

	for i, tc := range tcs {
		err := c.Verify(signer.Sign(bytes.NewReader(tc.in), tc.prefix))
		if err != nil {
			t.Errorf("TestRoundtrip %d: verify failed: %v\n", i, err)
		}
	}
}
