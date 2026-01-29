package cipher

import (
	"bytes"
	"testing"
)

func TestCipherDisabled(t *testing.T) {
	c := New("")
	plaintext := []byte("hello world")

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, plaintext) {
		t.Error("disabled cipher should return plaintext as-is")
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("disabled cipher decrypt should return ciphertext as-is")
	}
}

func TestCipherRoundTrip(t *testing.T) {
	c := New("mysecretkey")
	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted data should differ from plaintext")
	}
	if len(encrypted) != len(plaintext)+16 { // IV is 16 bytes
		t.Errorf("encrypted length = %d, want %d", len(encrypted), len(plaintext)+16)
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestCipherDifferentIV(t *testing.T) {
	c := New("testkey")
	plaintext := []byte("same input twice")

	enc1, _ := c.Encrypt(plaintext)
	enc2, _ := c.Encrypt(plaintext)

	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of the same plaintext should produce different ciphertext (different IV)")
	}

	dec1, _ := c.Decrypt(enc1)
	dec2, _ := c.Decrypt(enc2)
	if !bytes.Equal(dec1, dec2) {
		t.Error("both should decrypt to the same plaintext")
	}
}
