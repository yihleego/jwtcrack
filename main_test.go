package main

import (
	"crypto/sha256"
	"testing"
)

func TestJWTCrack(t *testing.T) {

}

func TestCrack(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.QXaZSGwc4eyj3SW_IkIVKsruB1H7WlOr3XMtw_LeODY"
	secret := "a2c4d"
	actual, err := crack(jwt, "abcde12345", 6, sha256.New)
	if err != nil {
		t.Error(err)
	}
	if actual != secret {
		t.Error("incorrect secret", secret, actual)
	}
	t.Logf("secret is '%s'", secret)
}
