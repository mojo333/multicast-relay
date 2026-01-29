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

	if c.NonceSize() != 0 {
		t.Errorf("disabled cipher NonceSize = %d, want 0", c.NonceSize())
	}
	if c.Overhead() != 0 {
		t.Errorf("disabled cipher Overhead = %d, want 0", c.Overhead())
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
	// GCM overhead = 12-byte nonce + 16-byte auth tag = 28 bytes
	expectedLen := len(plaintext) + c.NonceSize() + c.Overhead()
	if len(encrypted) != expectedLen {
		t.Errorf("encrypted length = %d, want %d (plaintext %d + nonce %d + tag %d)",
			len(encrypted), expectedLen, len(plaintext), c.NonceSize(), c.Overhead())
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestCipherDifferentNonce(t *testing.T) {
	c := New("testkey")
	plaintext := []byte("same input twice")

	enc1, _ := c.Encrypt(plaintext)
	enc2, _ := c.Encrypt(plaintext)

	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of the same plaintext should produce different ciphertext (different nonce)")
	}

	dec1, _ := c.Decrypt(enc1)
	dec2, _ := c.Decrypt(enc2)
	if !bytes.Equal(dec1, dec2) {
		t.Error("both should decrypt to the same plaintext")
	}
}

func TestCipherTamperDetection(t *testing.T) {
	c := New("tamperkey")
	plaintext := []byte("sensitive data that must not be tampered with")

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the ciphertext portion (after the nonce)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[c.NonceSize()+1] ^= 0xFF

	_, err = c.Decrypt(tampered)
	if err == nil {
		t.Error("decrypting tampered ciphertext should return an error")
	}
}

func TestCipherTruncatedCiphertext(t *testing.T) {
	c := New("trunckey")

	// Too short: less than nonce + auth tag
	short := make([]byte, c.NonceSize()+c.Overhead()-1)
	_, err := c.Decrypt(short)
	if err == nil {
		t.Error("decrypting truncated ciphertext should return an error")
	}
}

func TestCipherWrongKey(t *testing.T) {
	c1 := New("key-one")
	c2 := New("key-two")
	plaintext := []byte("encrypted with key one")

	encrypted, err := c1.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c2.Decrypt(encrypted)
	if err == nil {
		t.Error("decrypting with wrong key should return an error")
	}
}

func TestCipherNonceAndOverhead(t *testing.T) {
	c := New("sizecheck")

	// Standard GCM: 12-byte nonce, 16-byte auth tag
	if c.NonceSize() != 12 {
		t.Errorf("NonceSize = %d, want 12", c.NonceSize())
	}
	if c.Overhead() != 16 {
		t.Errorf("Overhead = %d, want 16", c.Overhead())
	}
}
