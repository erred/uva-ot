package sig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"go.seankhliao.com/signify"
)

const (
	MagicString = `AUTHSIGv0`

	pubLen = 42
	sigLen = 74
)

var (
	ErrNoSig   = errors.New("no signature found")
	ErrNoKeys  = errors.New("no keys found")
	ErrNotAuth = errors.New("not authorized")
)

// Verify matches the incoming data with the authorized hash-pubkeys in its config file,
// and attempts to validate the signatures.
// Hash is of the original file before a signature is appended
func (c *Config) Verify(r io.Reader) error {
	data, sig, err := Split(r)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)
	pks, ok := c.sha256key[hash]
	if !ok {
		return ErrNoKeys
	}

	for _, pk := range pks {
		if signify.Verify(pk, data, sig) {
			return nil
		}
	}

	for pk := range c.allowAll {
		if signify.Verify(&pk, data, sig) {
			return nil
		}
	}
	return ErrNotAuth
}

// Split reads the incoming stream and separates out the original file and the signature.
// The signature line format is documented at Signer.Sign
func Split(r io.Reader) (data []byte, sig *signify.Signature, err error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	i := bytes.LastIndex(b, []byte(MagicString))
	if i == -1 {
		return nil, nil, ErrNoSig
	}

	bb := bytes.SplitN(b[i:], []byte(`:`), 4)
	if len(bb) != 4 {
		return nil, nil, NewInvalidSig(nil, "expected 4 parts got %d", len(bb))
	}
	l, err := strconv.ParseInt(string(bb[1]), 10, 64)
	if err != nil {
		return nil, nil, NewInvalidSig(err, "parse original doc len")
	}
	sigb := make([]byte, sigLen)
	_, err = base64.StdEncoding.Decode(sigb, bb[2])
	if err != nil {
		return nil, nil, NewInvalidSig(err, "decode signature")
		// } else if n != sigLen {
		// 	return nil, nil, NewInvalidSig(nil, "signature len expected %d got %d", sigLen, n)
	}
	sig, err = signify.ParseSignature(sigb)
	if err != nil {
		return nil, nil, NewInvalidSig(err, "parse signature")
	}

	data = b[:l]
	return data, sig, nil
}

// ErrInvalidSig documents why the located signature is invalid
type ErrInvalidSig struct {
	err error
	msg string
}

func NewInvalidSig(err error, format string, args ...interface{}) ErrInvalidSig {
	return ErrInvalidSig{
		err: err,
		msg: fmt.Sprintf(format, args...),
	}
}
func (e ErrInvalidSig) Error() string {
	return fmt.Sprintf("invalid sig %s: %v", e.msg, e.err)
}
func (e ErrInvalidSig) Unwrap() error {
	return e.err
}
