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
	Algorithm = "HS256"
)

type task struct {
	ctx       context.Context
	alphabet  string           // alphabet is used to brute force
	letter    byte             // Each task assigns a letter
	maxLen    int              // combinations up to a certain length
	payload   []byte           // payload is used to generate a signature compared to the given signature
	signature []byte           // the given decoded base64 signature
	hash      func() hash.Hash // the chosen hash function for HMAC
}

func newTask(ctx context.Context, alphabet string, letter byte, maxLen int, payload []byte, signature []byte, hash func() hash.Hash) *task {
	return &task{ctx, alphabet, letter, maxLen, payload, signature, hash}
}

// run tries all the combinations of secret starting with letter
// and stopping at a maximum length of maxLen.
// It returns the secret when there is a match.
func (t *task) run() []byte {
	// Special case for length equals 1
	single := []byte{t.letter}
	if t.check(single) {
		return single
	}
	// Start from length 2
	buffer := make([]byte, t.maxLen+1)
	buffer[0] = t.letter
	for i := 2; i <= t.maxLen; i++ {
		if t.brute(buffer, 1, i) {
			return buffer[:i]
		}
	}
	return nil
}

// brute recursively generates all combinations for finding the secret.
// It returns true if it matches.
func (t *task) brute(buffer []byte, index int, maxDepth int) bool {
	for i := 0; i < len(t.alphabet); i++ {
		// The character at index in buffer successively takes the value of each letter in the alphabet.
		buffer[index] = t.alphabet[i]
		// If just changed the last letter that means it generated a permutation.
		// Otherwise, recurse to change the letter at the next index.
		if index == maxDepth-1 {
			// If this condition is met, it means the secret was found, otherwise continue.
			if t.check(buffer[:maxDepth]) {
				return true
			}
		} else {
			// If this condition is met, it means the secret was found.
			// Otherwise, it will continue and change the current character to the next letter.
			if t.brute(buffer, index+1, maxDepth) {
				return true
			}
		}
	}
	return false
}

// check if the signature produced with secret matches the given decoded base64 signature.
// It returns true if it matches.
func (t *task) check(secret []byte) bool {
	select {
	case <-t.ctx.Done():
		// Stop if the secret was found.
		runtime.Goexit()
		return false
	default:
		// Hash the buffer using HMAC.
		hm := hmac.New(t.hash, secret)
		hm.Write(t.payload)
		// Compare the computed hash to the given decoded base64 signature.
		return bytes.Compare(hm.Sum(nil), t.signature) == 0
	}
}

func main() {
	args := os.Args
	argc := len(args)
	if argc < 2 {
		fmt.Printf("Usage: %s <token> [alphabet] [maxlen] [algorithm]\nDefaults: alphabet=%s, maxlen=%d, algorithm=%s\n", args[0], Alphabet, MaxLen, Algorithm)
		return
	}

	alphabet := Alphabet
	maxLen := MaxLen
	algorithm := Algorithm
	jwt := args[1]
	if argc > 2 {
		alphabet = args[2]
	}
	if argc > 3 {
		v, err := strconv.Atoi(args[3])
		if err != nil {
			fmt.Printf("Invalid maxlen value %s (%d), defaults to %d\n", args[3], v, maxLen)
			return
		}
		if v > 0 {
			maxLen = v
		}
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
	// Split the JWT into header, payload and signature.
	parts := strings.Split(jwt, ".")
	headerBase64 := parts[0]
	payloadBase64 := parts[1]
	signatureBase64 := parts[2]
	// Recreate the part that is used to create the signature.
	body := []byte(headerBase64 + "." + payloadBase64)
	// Decode the signature.
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return "", err
	}
	// Create and execute tasks for each letter of the alphabet.
	count := len(alphabet)
	ctx, cancel := context.WithCancel(context.Background())
	secret := make(chan []byte, 1)
	tasks := make([]*task, count)
	for i := 0; i < count; i++ {
		tasks[i] = newTask(ctx, alphabet, alphabet[i], maxLen, body, signature, hash)
	}
	// Wait for all tasks to complete.
	wg := sync.WaitGroup{}
	wg.Add(count)
	for i := 0; i < count; i++ {
		t := tasks[i]
		go func() {
			defer wg.Done()
			res := t.run()
			// Stop all coroutines if the secret is found.
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
