// Package cipher provides AES-256-GCM authenticated encryption for remote relay connections.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Key derivation parameters. PBKDF2-HMAC-SHA256 with a high iteration count
// gives the passphrase a work factor, so a low-entropy shared key is no longer
// trivially brute-forceable from a captured frame or handshake. The salts are
// fixed (both relay ends derive the same key from the same passphrase) but
// distinct from any other use of the passphrase.
const (
	kdfIterations = 210_000
	kdfKeyLen     = 32
)

var hmacKDFSalt = []byte("multicast-relay-kdf-hmac-v1")

// errNoSession is returned when the passphrase-level cipher is asked to protect
// data. Only the per-connection ciphers from Session can do that.
var errNoSession = errors.New("cipher: no session key, use Session")

// Cipher handles HMAC-based peer authentication and AES-256-GCM encryption. One
// made by New authenticates peers and derives keys, while those made by Session
// protect a connection's data. Unlike the original CTR mode, GCM detects and
// rejects tampered ciphertext.
type Cipher struct {
	gcm     cipher.AEAD
	hmacKey []byte // retained for challenge-response peer authentication
	enabled bool
}

// New creates a new Cipher. If key is empty, encryption is disabled (passthrough).
// Otherwise the result authenticates peers with a key derived from the passphrase
// via PBKDF2-HMAC-SHA256, and Session provides the ciphers that protect data.
func New(key string) (*Cipher, error) {
	c := &Cipher{}
	if key == "" {
		return c, nil
	}

	hmacKey, err := pbkdf2.Key(sha256.New, key, hmacKDFSalt, kdfIterations, kdfKeyLen)
	if err != nil {
		return nil, fmt.Errorf("cipher: failed to derive HMAC key: %w", err)
	}

	c.hmacKey = hmacKey
	c.enabled = true
	return c, nil
}

// newGCM builds an AES-256-GCM AEAD and zeroes the key once it is loaded.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("cipher: failed to create AES block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher: failed to create GCM: %w", err)
	}
	return gcm, nil
}

// Session derives the encryption keys for one authenticated connection from both
// handshake challenges, one key per direction. A frame therefore cannot be
// replayed on another connection or reflected back to its sender. Respond only
// ever signs 16-byte challenges for a peer, so the longer, labelled input used
// here cannot be obtained through the handshake.
func (c *Cipher) Session(serverChallenge, clientChallenge []byte) (toServer, toClient *Cipher, err error) {
	derive := func(direction string) (*Cipher, error) {
		input := []byte("multicast-relay-session-v1:" + direction)
		input = append(input, serverChallenge...)
		input = append(input, clientChallenge...)
		gcm, err := newGCM(c.Respond(input))
		if err != nil {
			return nil, err
		}
		return &Cipher{gcm: gcm, enabled: true}, nil
	}
	if toServer, err = derive("to-server"); err != nil {
		return nil, nil, err
	}
	if toClient, err = derive("to-client"); err != nil {
		return nil, nil, err
	}
	return toServer, toClient, nil
}

// Enabled reports whether encryption and peer authentication are active.
func (c *Cipher) Enabled() bool {
	return c.enabled
}

// maxFrameBody is the largest frame body the 2-byte length prefix can describe.
const maxFrameBody = 0xffff

// EncryptFrame encrypts plaintext and returns a single wire frame in one allocation:
// [2-byte big-endian length][nonce(12)][ciphertext+tag] when AES is enabled,
// or [2-byte length][plaintext] when AES is disabled.
// Returns an error if the frame body would exceed what the length prefix can
// represent, because the uint16 cast would otherwise silently corrupt the framing.
func (c *Cipher) EncryptFrame(plaintext []byte) ([]byte, error) {
	if !c.enabled {
		if len(plaintext) > maxFrameBody {
			return nil, fmt.Errorf("cipher: plaintext too large for frame: %d bytes (max %d)", len(plaintext), maxFrameBody)
		}
		frame := make([]byte, 2+len(plaintext))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(plaintext)))
		copy(frame[2:], plaintext)
		return frame, nil
	}
	if c.gcm == nil {
		return nil, errNoSession
	}
	ns := c.gcm.NonceSize()
	if ns+len(plaintext)+c.gcm.Overhead() > maxFrameBody {
		return nil, fmt.Errorf("cipher: plaintext too large for frame: %d bytes (max %d)", len(plaintext), maxFrameBody-ns-c.gcm.Overhead())
	}
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

// Decrypt decrypts and verifies a frame body (nonce || ciphertext || tag) using
// AES-256-GCM.
// Returns an error if the ciphertext was tampered with or truncated.
// If no key, returns ciphertext as-is.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if !c.enabled {
		return ciphertext, nil
	}

	if c.gcm == nil {
		return nil, errNoSession
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
