// Package cipher provides AES-256-CTR encryption for remote relay connections.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// Cipher handles AES-256-CTR encryption and decryption.
type Cipher struct {
	key       []byte
	blockSize int
	enabled   bool
}

// New creates a new Cipher. If key is empty, encryption is disabled (passthrough).
func New(key string) *Cipher {
	c := &Cipher{}
	if key == "" {
		return c
	}
	hash := sha256.Sum256([]byte(key))
	c.key = hash[:]
	c.blockSize = aes.BlockSize
	c.enabled = true
	return c
}

// Encrypt encrypts plaintext using AES-256-CTR. If no key, returns plaintext as-is.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if !c.enabled {
		return plaintext, nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(iv)+len(plaintext))
	copy(ciphertext, iv)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[len(iv):], plaintext)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-CTR. If no key, returns ciphertext as-is.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if !c.enabled {
		return ciphertext, nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < c.blockSize {
		return nil, err
	}

	iv := ciphertext[:c.blockSize]
	data := ciphertext[c.blockSize:]

	plaintext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, data)

	return plaintext, nil
}
