// Package cipher provides AES-256-CTR encryption for remote relay connections.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Cipher handles AES-256-CTR encryption and decryption.
type Cipher struct {
	block     cipher.Block
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
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		// sha256 always produces 32 bytes, which is a valid AES-256 key,
		// so this should never happen.
		panic("cipher: failed to create AES block: " + err.Error())
	}
	c.block = block
	c.blockSize = aes.BlockSize
	c.enabled = true
	return c
}

// Encrypt encrypts plaintext using AES-256-CTR. If no key, returns plaintext as-is.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if !c.enabled {
		return plaintext, nil
	}

	iv := make([]byte, c.blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, c.blockSize+len(plaintext))
	copy(ciphertext, iv)

	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(ciphertext[c.blockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-CTR. If no key, returns ciphertext as-is.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if !c.enabled {
		return ciphertext, nil
	}

	if len(ciphertext) < c.blockSize {
		return nil, errors.New("cipher: ciphertext too short")
	}

	iv := ciphertext[:c.blockSize]
	data := ciphertext[c.blockSize:]

	plaintext := make([]byte, len(data))
	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(plaintext, data)

	return plaintext, nil
}
