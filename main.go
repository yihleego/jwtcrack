package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	Alphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	MaxLen    = 6
	Algorithm = "sha256"
)

func main() {
	args := os.Args
	argc := len(args)
	alphabet := Alphabet
	maxLen := MaxLen
	algorithm := Algorithm
	if argc < 2 {
		fmt.Printf("%s <token> [alphabet] [max_len] [algorithm]\nDefaults: alphabet=%s, max_len=%d, algorithm=%s\n", args[0], alphabet, maxLen, algorithm)
		return
	}
	jwt := args[1]
	if argc > 2 {
		alphabet = args[2]
	}
	if argc > 3 {
		v, err := strconv.Atoi(args[3])
		if err != nil {
			fmt.Printf("Invalid max_len value %s (%d), defaults to %d\n", args[3], v, maxLen)
			return
		}
		maxLen = v
	}
	if argc > 4 {
		algorithm = args[4]
	}
	var hf func() hash.Hash
	switch algorithm {
	case "HS256":
		hf = sha256.New
	case "HS384":
		hf = sha512.New384
	case "HS512":
		hf = sha512.New
	default:
		fmt.Printf("Invalid algorithm %s\n", algorithm)
		return
	}
	secret, err := crack(jwt, alphabet, maxLen, hf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Secret is \"%s\"\n", secret)
}

func crack(jwt, alphabet string, maxLen int, hash func() hash.Hash) (string, error) {
	parts := strings.Split(jwt, ".")
	headerBase64 := parts[0]
	payloadBase64 := parts[1]
	signatureBase64 := parts[2]
	encrypt := []byte(headerBase64 + "." + payloadBase64)
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return "", err
	}
	result := make(chan []byte, 1)
	wg := sync.WaitGroup{}
	for i := 0; i < len(alphabet); i++ {
		wg.Add(1)
		index := i
		go func() {
			brute(alphabet, index, maxLen, encrypt, signature, hash, result)
			wg.Done()
		}()
	}
	wg.Wait()
	close(result)
	secret, ok := <-result
	if ok {
		return string(secret), nil
	} else {
		return "", errors.New("no secret found")
	}
}

func brute(alphabet string, index int, maxLen int, encrypt []byte, signature []byte, hash func() hash.Hash, secret chan []byte) {
	special := []byte{alphabet[index]}
	if check(encrypt, signature, special, hash) {
		secret <- special
		return
	}
	buf := make([]byte, maxLen+1)
	buf[0] = alphabet[index]
	for i := 2; i <= maxLen; i++ {
		if impl(buf, 1, i, alphabet, encrypt, signature, hash) {
			secret <- buf[:i]
			return
		}
	}
}

func check(payload []byte, signature []byte, secret []byte, hash func() hash.Hash) bool {
	hm := hmac.New(hash, secret)
	hm.Write(payload)
	return bytes.Compare(hm.Sum(nil), signature) == 0
}

func impl(buf []byte, index int, maxDepth int, alphabet string, encrypt []byte, signature []byte, hash func() hash.Hash) bool {
	for i := 0; i < len(alphabet); i++ {
		buf[index] = alphabet[i]
		if index == maxDepth-1 {
			if check(encrypt, signature, buf[:maxDepth], hash) {
				return true
			}
		} else {
			if impl(buf, index+1, maxDepth, alphabet, encrypt, signature, hash) {
				return true
			}
		}
	}
	return false
}
