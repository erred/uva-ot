package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"go.seankhliao.com/uva-ot/sig"
)

func main() {
	var inPlace bool
	var sec, pass, prefix string
	flag.StringVar(&pass, "pass", os.Getenv("SIGNER_PASS"), "security key password, defaults to env SIGNER_PASS")
	flag.StringVar(&sec, "s", os.Getenv("SIGNER_SECKEY"), "signing security key, defaults to env SIGNER_SECKEY")
	flag.StringVar(&prefix, "prefix", "", "prefix to signature line, ex '# ' for scripts")
	flag.BoolVar(&inPlace, "i", false, "inplace: overwrite existing file")
	flag.Parse()

	if sec == "" {
		flag.Usage()
		log.Fatal("missing sec key")
	}
	s, err := sig.NewSigner(sec, pass)
	if err != nil {
		log.Fatal("prepare signer: ", err)
	}

	for _, a := range flag.Args() {
		err = sign(s, prefix, a, inPlace)
		if err != nil {
			log.Fatalf("processing %s err: %v\n", a, err)
		}
	}
}

func sign(s *sig.Signer, prefix, file string, inPlace bool) error {
	if inPlace {
		f, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("open inplace: %w", err)
		}
		defer f.Close()
		b, err := ioutil.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read inplace: %w", err)
		}
		_, err = f.WriteString(s.Signature(b, prefix))
		if err != nil {
			return fmt.Errorf("write inplace: %w", err)
		}
	} else {
		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("open orig: %w", err)
		}
		defer f.Close()
		out, err := os.Create(file + ".signed")
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer out.Close()
		_, err = io.Copy(out, s.Sign(f, prefix))
		if err != nil {
			return fmt.Errorf("copy to output: %w", err)
		}
	}
	return nil
}
