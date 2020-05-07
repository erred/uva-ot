package sig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"go.seankhliao.com/signify"
)

// Signer is used for signing files
type Signer struct {
	PrivateKey *signify.PrivateKey
}

// NewSigner creates a Signer for signing files for Verify.
// key is a base64 encoded private/seckey,
// passphrase is the optional passphrase,
func NewSigner(key, passphrase string) (*Signer, error) {
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
	}, nil
}

// Sign buffers the incoming reader,
// and returns the same data with a signature line appended
// with the format "\nPrefix:MagicString:OriginalLen:Base64Signature:\n"
// prefix is the string to prepend to the signature line, ex "# " for bash scripts
func (s Signer) Sign(r io.Reader, prefix string) io.Reader {
	var buf bytes.Buffer
	io.Copy(&buf, r)
	buf.WriteString(s.Signature(buf.Bytes(), prefix))
	return &buf
}

func (s Signer) Signature(b []byte, prefix string) string {
	sigb := signify.MarshalSignature(signify.Sign(s.PrivateKey, b))
	sig := base64.StdEncoding.EncodeToString(sigb)
	return fmt.Sprintf("\n%s:%s:%d:%s:", prefix, MagicString, len(b), sig)
}
