package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	Alphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	MaxLen    = 6
	Algorithm = "sha256"
)

type task struct {
	ctx       context.Context
	alphabet  string
	letter    byte
	maxLen    int
	payload   []byte
	signature []byte
	hash      func() hash.Hash
}

func newTask(ctx context.Context, alphabet string, letter byte, maxLen int, payload []byte, signature []byte, hash func() hash.Hash) *task {
	return &task{ctx, alphabet, letter, maxLen, payload, signature, hash}
}

func (t *task) run() []byte {
	special := []byte{t.letter}
	if t.check(special) {
		return special
	}
	buffer := make([]byte, t.maxLen+1)
	buffer[0] = t.letter
	for i := 2; i <= t.maxLen; i++ {
		if t.brute(buffer, 1, i) {
			return buffer[:i]
		}
	}
	return nil
}

func (t *task) brute(buffer []byte, index int, maxDepth int) bool {
	for i := 0; i < len(t.alphabet); i++ {
		buffer[index] = t.alphabet[i]
		if index == maxDepth-1 {
			if t.check(buffer[:maxDepth]) {
				return true
			}
		} else {
			if t.brute(buffer, index+1, maxDepth) {
				return true
			}
		}
	}
	return false
}

func (t *task) check(secret []byte) bool {
	select {
	case <-t.ctx.Done():
		runtime.Goexit()
		return false
	default:
		hm := hmac.New(t.hash, secret)
		hm.Write(t.payload)
		return bytes.Compare(hm.Sum(nil), t.signature) == 0
	}
}

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
	encrypt := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	secret := make(chan []byte, 1)
	tasks := make([]*task, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		tasks[i] = newTask(ctx, alphabet, alphabet[i], maxLen, encrypt, signature, hash)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < len(tasks); i++ {
		wg.Add(1)
		t := tasks[i]
		go func() {
			defer wg.Done()
			res := t.run()
			if res != nil {
				cancel()
				secret <- res
			}
		}()
	}
	wg.Wait()
	cancel()
	close(secret)
	v, ok := <-secret
	if ok {
		return string(v), nil
	} else {
		return "", errors.New("no secret found")
	}
}
