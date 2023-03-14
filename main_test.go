package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestHS256(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.QXaZSGwc4eyj3SW_IkIVKsruB1H7WlOr3XMtw_LeODY"
	secret := "a2c4d"
	actual, err := crack(jwt, "abcde12345", 6, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	if actual != secret {
		t.Fatal("incorrect secret", secret, actual)
	}
	t.Logf("secret is '%s'", secret)
}

func TestHS384(t *testing.T) {
	jwt := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.kh07R5GxeApHgXnfm_3CpRo8Ky1ZD66zCb-lk-9-AQb549c50PU1c8BBSxkDewlm"
	secret := "a2c4d"
	actual, err := crack(jwt, "abcde12345", 6, sha512.New384)
	if err != nil {
		t.Fatal(err)
	}
	if actual != secret {
		t.Fatal("incorrect secret", secret, actual)
	}
	t.Logf("secret is '%s'", secret)
}

func TestHS512(t *testing.T) {
	jwt := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.6J3aomWAWAA-K2goUqsgi9VJJ4O6tuG-xe-_nmWr1UMzj79B9sBQumpPtWYQ4geYx5wckFLnd_9rXpdyFv-sRw"
	secret := "a2c4d"
	actual, err := crack(jwt, "abcde12345", 6, sha512.New)
	if err != nil {
		t.Fatal(err)
	}
	if actual != secret {
		t.Fatal("incorrect secret", secret, actual)
	}
	t.Logf("secret is '%s'", secret)
}
