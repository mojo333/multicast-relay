// Package cipher provides AES-256-GCM authenticated encryption for remote relay connections.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Cipher handles AES-256-GCM authenticated encryption and decryption.
// GCM provides both confidentiality and integrity — unlike the original CTR mode,
// tampered ciphertext is detected and rejected.
type Cipher struct {
	gcm     cipher.AEAD
	enabled bool
}

// New creates a new Cipher. If key is empty, encryption is disabled (passthrough).
func New(key string) *Cipher {
	c := &Cipher{}
	if key == "" {
		return c
	}
	hash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		// sha256 always produces 32 bytes, which is a valid AES-256 key,
		// so this should never happen.
		panic("cipher: failed to create AES block: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher: failed to create GCM: " + err.Error())
	}
	c.gcm = gcm
	c.enabled = true
	return c
}

// NonceSize returns the nonce size used by the cipher (12 bytes for GCM).
// Returns 0 when encryption is disabled.
func (c *Cipher) NonceSize() int {
	if !c.enabled {
		return 0
	}
	return c.gcm.NonceSize()
}

// Overhead returns the authentication tag overhead (16 bytes for GCM).
// Returns 0 when encryption is disabled.
func (c *Cipher) Overhead() int {
	if !c.enabled {
		return 0
	}
	return c.gcm.Overhead()
}

// Encrypt encrypts and authenticates plaintext using AES-256-GCM.
// Output format: nonce (12 bytes) || ciphertext || auth tag (16 bytes).
// If no key, returns plaintext as-is.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if !c.enabled {
		return plaintext, nil
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext+tag to nonce
	return c.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts and verifies ciphertext using AES-256-GCM.
// Returns an error if the ciphertext was tampered with or truncated.
// If no key, returns ciphertext as-is.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if !c.enabled {
		return ciphertext, nil
	}

	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize+c.gcm.Overhead() {
		return nil, errors.New("cipher: ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	plaintext, err := c.gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("cipher: authentication failed (tampered or wrong key)")
	}

	return plaintext, nil
}
