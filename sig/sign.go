package sig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ebfe/signify"
)

// Signer is used for signing files
type Signer struct {
	PrivateKey *signify.PrivateKey
	Prefix     string
}

// NewSigner creates a Signer for signing files for Verify.
// key is a base64 encoded private/seckey,
// passphrase is the optional passphrase,
// prefix if the string to prepend to the signature line, ex "# " for bash scripts
func NewSigner(key, passphrase, prefix string) (*Signer, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	pk, err := signify.ParsePrivateKey(b, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	return &Signer{
		PrivateKey: pk,
		Prefix:     prefix,
	}, nil
}

// Sign buffers the incoming reader,
// and returns the same data with a signature line appended
// with the format "\nPrefix:MagicString:OriginalLen:Base64Signature:"
func (s Signer) Sign(r io.Reader) io.Reader {
	var buf bytes.Buffer
	io.Copy(&buf, r)
	l := buf.Len()
	sigb := signify.MarshalSignature(signify.Sign(s.PrivateKey, buf.Bytes()))
	sig := base64.StdEncoding.EncodeToString(sigb)
	buf.WriteString(fmt.Sprintf("\n%s:%s:%d:%s:", s.Prefix, MagicString, l, sig))
	return &buf
}
