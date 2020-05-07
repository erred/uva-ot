package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"go.seankhliao.com/signify"
	"go.seankhliao.com/uva-ot/sig"
	"sigs.k8s.io/yaml"
)

func main() {
	var db, sec, pass, prefix string
	flag.StringVar(&db, "db", "-", "db file to update, '-' for none")
	flag.StringVar(&sec, "s", "", "sec key file")
	flag.StringVar(&pass, "pass", "", "sec key passphrase")
	flag.StringVar(&prefix, "prefix", "", "prefix to signature line")
	flag.Parse()

	if sec == "" {
		flag.Usage()
		log.Fatal("-s is mandatory")
	}
	s, pub, err := keypair(sec, pass)
	if err != nil {
		log.Fatal("prepare keys: ", err)
	}
	add, save, err := database(db, pub)
	if err != nil {
		log.Fatal("prepare database: ", err)
	}
	defer save()

	for _, a := range flag.Args() {
		hash, err := sign(s, prefix, a)
		if err != nil {
			log.Fatalf("signing %s: %v", a, err)
		}
		add(hash)
	}
}

func keypair(fp, pass string) (signer *sig.Signer, pubkey string, err error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", fp, err)
	}
	defer f.Close()
	_, b, err := signify.ReadFile(f)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", fp, err)
	}
	s, err := signify.ParsePrivateKey(b, []byte(pass))
	if err != nil {
		return nil, "", fmt.Errorf("parse privkey: %w", err)
	}
	signer = &sig.Signer{PrivateKey: s}

	pkb := ed25519.PrivateKey(signer.PrivateKey.Bytes[:]).Public().(ed25519.PublicKey)
	var pka [ed25519.PublicKeySize]byte
	copy(pka[:], pkb)
	pubkey = base64.StdEncoding.EncodeToString(signify.MarshalPublicKey(&signify.PublicKey{
		Bytes:       pka,
		Fingerprint: signer.PrivateKey.Fingerprint,
	}))
	return signer, pubkey, nil
}

func database(fp, pubkey string) (add func(string), save func(), err error) {
	c, err := sig.NewConfigFromFile(fp)
	if os.IsNotExist(err) {
		c = &sig.Config{}
	} else if err != nil {
		log.Fatal("read db %s: %v", fp, err)
	}
	pki := -1
	for i, key := range c.Keys {
		if key.Pubkey == pubkey {
			pki = i
			break
		}
	}
	if pki == -1 {
		pki = len(c.Keys)
		c.Keys = append(c.Keys, sig.Key{
			Pubkey: pubkey,
		})
	}

	add = func(hash string) {
		c.Keys[pki].Sha256 = append(c.Keys[pki].Sha256, sig.AllowedItem{
			Hash: hash,
		})
	}
	save = func() {
		b, err := yaml.Marshal(c)
		if err != nil {
			log.Fatal("marshal db: ", err)
		}
		err = ioutil.WriteFile(fp, b, 0644)
		if err != nil {
			log.Fatal("write db: ", err)
		}
	}
	return add, save, nil
}

func sign(s *sig.Signer, prefix, fp string) (string, error) {
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	sha := sha256.Sum256(b)
	b = append(b, []byte(s.Signature(b, prefix))...)

	err = ioutil.WriteFile(fp, b, 0o644)
	if err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}
	return hex.EncodeToString(sha[:]), nil
}
