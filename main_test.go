package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// these mirror https://github.com/florolf/pbotp/blob/master/doc/proto.md

func TestDocCode(t *testing.T) {
	privKey, _ := base64.RawURLEncoding.DecodeString("zGRMAXRoSKwMZG5EM-_B-s8oxTfICcfBiN1PAHCCqVo")
	challenge, _ := hex.DecodeString("d121728ed9fef9dcf42bcadf0a60deb07134f1896fb7991f1684dddd6ba8b623")
	payload := []byte("dev\x00SSSN7PBXFG6DY\x00root\x00")

	r, err := NewResponder(privKey, ModeCode, 9)
	if err != nil {
		t.Fatalf("creating responder failed: %v", err)
	}

	response, err := r.Response(payload, challenge)
	responseExpected := "526 044 548"
	if response != responseExpected {
		t.Errorf("expected response %s, got %s", responseExpected, response)
	}
}

func TestDocPhrase(t *testing.T) {
	privKey, _ := base64.RawURLEncoding.DecodeString("zGRMAXRoSKwMZG5EM-_B-s8oxTfICcfBiN1PAHCCqVo")
	challenge, _ := hex.DecodeString("d121728ed9fef9dcf42bcadf0a60deb07134f1896fb7991f1684dddd6ba8b623")
	payload := []byte("dev\x00SSSN7PBXFG6DY\x00root\x00")

	r, err := NewResponder(privKey, ModePhrase, 4)
	if err != nil {
		t.Fatalf("creating responder failed: %v", err)
	}

	response, err := r.Response(payload, challenge)
	responseExpected := "correct horse avocado cupboard"
	if response != responseExpected {
		t.Errorf("expected response %s, got %s", responseExpected, response)
	}
}
