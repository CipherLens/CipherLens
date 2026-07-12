package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
)

const canonicalPublicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuwlKS6Lv26yM7IiRN6Ob3h/AfCcQtwcOZbyFz/kjCLgTR0c/Ry6iyZew2J8SY6MCdjUC7FaOaXaf0ajdKImwmdNW5IzS0ltOZxmD8YpCxyoDjjrmhiDEbwuXFcuCIoAEPpUppqC1GXkTl6lk8xmlx/JywnJqKSG6IawYJcGyf+wIDAQAB"

type corpusCase struct {
	name string
	der  []byte
}

type result struct {
	Implementation      string `json:"implementation"`
	Revision            string `json:"revision"`
	Case                string `json:"case"`
	Accepted            bool   `json:"accepted"`
	CanonicalSPKISHA256 string `json:"canonical_spki_sha256"`
	KeyEqual            bool   `json:"key_equal"`
	Error               string `json:"error"`
}

func appendTail(input []byte, tail ...byte) []byte {
	output := append([]byte(nil), input...)
	return append(output, tail...)
}

func rsaEqual(a, b *rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func main() {
	canonical, err := base64.StdEncoding.DecodeString(canonicalPublicKeyBase64)
	if err != nil {
		panic(err)
	}
	referenceAny, err := x509.ParsePKIXPublicKey(canonical)
	if err != nil {
		panic(err)
	}
	reference := referenceAny.(*rsa.PublicKey)

	changedN := new(big.Int).Add(reference.N, big.NewInt(2))
	different, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{
		N: changedN,
		E: reference.E,
	})
	if err != nil {
		panic(err)
	}

	cases := []corpusCase{
		{"canonical", canonical},
		{"tail_0500", appendTail(canonical, 0x05, 0x00)},
		{"tail_3000", appendTail(canonical, 0x30, 0x00)},
		{"tail_020100", appendTail(canonical, 0x02, 0x01, 0x00)},
		{"invalid_der", []byte{0x30, 0x00}},
		{"different_key", different},
	}

	encoder := json.NewEncoder(os.Stdout)
	for _, testCase := range cases {
		row := result{
			Implementation: "go_crypto_x509",
			Revision:       runtime.Version(),
			Case:           testCase.name,
		}
		parsedAny, parseErr := x509.ParsePKIXPublicKey(testCase.der)
		if parseErr != nil {
			row.Error = parseErr.Error()
		} else {
			parsed, ok := parsedAny.(*rsa.PublicKey)
			if !ok {
				row.Error = fmt.Sprintf("unexpected key type %T", parsedAny)
			} else {
				normalized, marshalErr := x509.MarshalPKIXPublicKey(parsed)
				if marshalErr != nil {
					row.Error = marshalErr.Error()
				} else {
					digest := sha256.Sum256(normalized)
					row.Accepted = true
					row.CanonicalSPKISHA256 = hex.EncodeToString(digest[:])
					row.KeyEqual = rsaEqual(reference, parsed)
					if testCase.name == "canonical" &&
						!bytes.Equal(normalized, canonical) {
						row.Error = "canonical roundtrip mismatch"
						row.Accepted = false
					}
				}
			}
		}
		if err := encoder.Encode(row); err != nil {
			panic(err)
		}
	}
}
