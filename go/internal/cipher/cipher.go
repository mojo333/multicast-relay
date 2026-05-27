// Package cipher provides AES-256-GCM authenticated encryption for remote relay connections.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Cipher handles AES-256-GCM authenticated encryption and HMAC-based peer authentication.
// GCM provides both confidentiality and integrity — unlike the original CTR mode,
// tampered ciphertext is detected and rejected.
type Cipher struct {
	gcm     cipher.AEAD
	hmacKey []byte // retained for challenge-response peer authentication
	enabled bool
}

// New creates a new Cipher. If key is empty, encryption is disabled (passthrough).
// When key is non-empty, two separate keys are derived via SHA-256 with domain separation:
//   - AES key:  SHA-256(passphrase)
//   - HMAC key: SHA-256("multicast-relay-auth-v1:" + passphrase)
func New(key string) (*Cipher, error) {
	c := &Cipher{}
	if key == "" {
		return c, nil
	}

	keyBytes := []byte(key)

	// Derive AES-256 key and zero the intermediate hash immediately after loading into the block cipher.
	aesHash := sha256.Sum256(keyBytes)
	block, err := aes.NewCipher(aesHash[:])
	for i := range aesHash {
		aesHash[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("cipher: failed to create AES block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher: failed to create GCM: %w", err)
	}

	// Derive HMAC key with explicit domain separation so AES key ≠ HMAC key for the same passphrase.
	hmacInput := append([]byte("multicast-relay-auth-v1:"), keyBytes...)
	hmacHash := sha256.Sum256(hmacInput)
	for i := range hmacInput {
		hmacInput[i] = 0
	}
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	c.gcm = gcm
	c.hmacKey = make([]byte, len(hmacHash))
	copy(c.hmacKey, hmacHash[:])
	for i := range hmacHash {
		hmacHash[i] = 0
	}

	c.enabled = true
	return c, nil
}

// Enabled reports whether encryption and peer authentication are active.
func (c *Cipher) Enabled() bool {
	return c.enabled
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

// EncryptFrame encrypts plaintext and returns a single wire frame in one allocation:
// [2-byte big-endian length][nonce(12)][ciphertext+tag] when AES is enabled,
// or [2-byte length][plaintext] when AES is disabled.
func (c *Cipher) EncryptFrame(plaintext []byte) ([]byte, error) {
	if !c.enabled {
		frame := make([]byte, 2+len(plaintext))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(plaintext)))
		copy(frame[2:], plaintext)
		return frame, nil
	}
	ns := c.gcm.NonceSize()
	// Pre-allocate: 2-byte length prefix + nonce + plaintext + GCM tag.
	frame := make([]byte, 2+ns, 2+ns+len(plaintext)+c.gcm.Overhead())
	if _, err := io.ReadFull(rand.Reader, frame[2:2+ns]); err != nil {
		return nil, err
	}
	nonce := frame[2 : 2+ns]
	sealed := c.gcm.Seal(frame, nonce, plaintext, nil)
	binary.BigEndian.PutUint16(sealed[0:2], uint16(len(sealed)-2))
	return sealed, nil
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

// Challenge generates a 16-byte random nonce for the peer authentication handshake.
// Returns nil, nil when encryption is disabled (no shared key to authenticate with).
func (c *Cipher) Challenge() ([]byte, error) {
	if !c.enabled {
		return nil, nil
	}
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return nil, fmt.Errorf("cipher: challenge generation failed: %w", err)
	}
	return challenge, nil
}

// Respond computes HMAC-SHA256(hmacKey, challenge) for the peer auth handshake.
// Returns nil when encryption is disabled.
func (c *Cipher) Respond(challenge []byte) []byte {
	if !c.enabled {
		return nil
	}
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(challenge)
	return mac.Sum(nil)
}

// Verify checks whether response equals HMAC-SHA256(hmacKey, challenge)
// using constant-time comparison to prevent timing attacks.
// Returns false when encryption is disabled.
func (c *Cipher) Verify(challenge, response []byte) bool {
	if !c.enabled || len(response) != sha256.Size {
		return false
	}
	expected := c.Respond(challenge)
	return hmac.Equal(expected, response)
}
