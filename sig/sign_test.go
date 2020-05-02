package sig

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewSigner(t *testing.T) {
	tcs := []struct {
		key  string
		pass string
	}{
		{"RWRCSwAAAADT8wEq1jVIbR5rPmYXJ4DS8Hbn/jNsuDyPK7F+TwZRwsCYW4XSvRdf68DjptL3EErgg1uPlsNJ2QbZyMG5eg5CKUkvPS0Cd9iuJAfdK6SvcljYwddrtog9WY0p9KXSbQo=",
			"",
		}, {
			"RWRCSwAAACpvIeeT473gLDJH4+X1NDb8KXWmT01fWTmJO0GeSJlVRz2wIl/2zxSB6/8pbQegxgG0ZQ9tBxrrJ85X3YyFmMR9MGyMlZsGXgkGYijr0syippenYAe14qrWt8FSqTpo3gc=",
			"signifyisdope",
		},
	}
	for i, tc := range tcs {
		if _, err := NewSigner(tc.key, tc.pass); err != nil {
			t.Errorf("TestNewSigner %d: err: %v\n", i, err)
		}
	}
}

func TestSign(t *testing.T) {
	signer, err := NewSigner("RWRCSwAAAAB/LS7sgYhbtA0E8k4e7T0VJfod6GIOYxv1JFtHhbzLGcb9N5XaHxYOpw6DE2gikozUxjL/Z7MdM/5WBU0lRoH52Zya3AIL/axSMraYMq4eRy9LjJdsodkCEZ38O4Ys2qI=", "")
	if err != nil {
		t.Errorf("TestSign setup: parse sec key: %v\n", err)
		t.FailNow()
	}

	tcs := []struct {
		prefix string
		in     []byte
		out    []byte
	}{
		{
			"# ",
			[]byte(`#!/usr/bin/env bash
echo hello world
`),
			[]byte(`#!/usr/bin/env bash
echo hello world

# :AUTHSIGv0:37:RWT1JFtHhbzLGXqMPIXetBWUKEKVaTSFyhLiCPJOsCscn5qWcpHey0Euj0Emi5H29QchhsxfyeQZBqLM2GA6YqlIJn/OpT1x5Ac=:`),
		},
	}

	for i, tc := range tcs {
		b, err := ioutil.ReadAll(signer.Sign(bytes.NewReader(tc.in), tc.prefix))
		if err != nil {
			t.Errorf("TestSign %d: read result: %v\n", i, err)
			continue
		}
		if !cmp.Equal(b, tc.out) {
			fmt.Println(len(tc.in))
			t.Errorf("TestSign %d: unequal diff:\n%s\n", i, cmp.Diff(b, tc.out))
		}
	}
}
