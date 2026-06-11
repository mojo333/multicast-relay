package cipher

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func mustNew(t *testing.T, key string) *Cipher {
	t.Helper()
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCipherDisabled(t *testing.T) {
	c := mustNew(t, "")
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
	c := mustNew(t, "mysecretkey")
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
	c := mustNew(t, "testkey")
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
	c := mustNew(t, "tamperkey")
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
	c := mustNew(t, "trunckey")

	// Too short: less than nonce + auth tag
	short := make([]byte, c.NonceSize()+c.Overhead()-1)
	_, err := c.Decrypt(short)
	if err == nil {
		t.Error("decrypting truncated ciphertext should return an error")
	}
}

func TestCipherWrongKey(t *testing.T) {
	c1 := mustNew(t, "key-one")
	c2 := mustNew(t, "key-two")
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
	c := mustNew(t, "sizecheck")

	// Standard GCM: 12-byte nonce, 16-byte auth tag
	if c.NonceSize() != 12 {
		t.Errorf("NonceSize = %d, want 12", c.NonceSize())
	}
	if c.Overhead() != 16 {
		t.Errorf("Overhead = %d, want 16", c.Overhead())
	}
}

func TestEncryptFrame(t *testing.T) {
	tests := []struct {
		name string
		key  string
		data []byte
	}{
		{"disabled empty plaintext", "", nil},
		{"disabled with data", "", []byte("hello")},
		{"enabled empty plaintext", "secret", nil},
		{"enabled with data", "secret", []byte("the quick brown fox")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustNew(t, tt.key)

			frame, err := c.EncryptFrame(tt.data)
			if err != nil {
				t.Fatalf("EncryptFrame() error = %v", err)
			}

			if len(frame) < 2 {
				t.Fatalf("frame too short: %d bytes", len(frame))
			}
			bodyLen := int(binary.BigEndian.Uint16(frame[:2]))
			if bodyLen != len(frame)-2 {
				t.Errorf("length prefix = %d, want %d", bodyLen, len(frame)-2)
			}

			decrypted, err := c.Decrypt(frame[2:])
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(decrypted, tt.data) {
				t.Errorf("round-trip mismatch: got %q, want %q", decrypted, tt.data)
			}
		})
	}
}

func TestEncryptFrameSizeLimit(t *testing.T) {
	// The 2-byte length prefix caps the frame body at 65535 bytes.
	// Enabled overhead: nonce (12) + GCM tag (16) = 28 bytes.
	tests := []struct {
		name    string
		key     string
		size    int
		wantErr bool
	}{
		{"disabled at limit", "", 0xffff, false},
		{"disabled over limit", "", 0xffff + 1, true},
		{"enabled at limit", "secret", 0xffff - 28, false},
		{"enabled over limit", "secret", 0xffff - 27, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustNew(t, tt.key)

			frame, err := c.EncryptFrame(make([]byte, tt.size))

			if tt.wantErr {
				if err == nil {
					t.Fatal("EncryptFrame() expected error for oversized plaintext, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncryptFrame() error = %v", err)
			}
			bodyLen := int(binary.BigEndian.Uint16(frame[:2]))
			if bodyLen != len(frame)-2 {
				t.Errorf("length prefix = %d, want %d (silent truncation?)", bodyLen, len(frame)-2)
			}
		})
	}
}

func TestChallengeRespondVerify(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		mutate func(challenge, response []byte) ([]byte, []byte)
		want   bool
	}{
		{"valid response", "secret", nil, true},
		{
			"tampered response", "secret",
			func(ch, rsp []byte) ([]byte, []byte) {
				rsp[0] ^= 0xff
				return ch, rsp
			},
			false,
		},
		{
			"truncated response", "secret",
			func(ch, rsp []byte) ([]byte, []byte) {
				return ch, rsp[:len(rsp)-1]
			},
			false,
		},
		{
			"different challenge", "secret",
			func(ch, rsp []byte) ([]byte, []byte) {
				other := make([]byte, len(ch))
				return other, rsp
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustNew(t, tt.key)

			challenge, err := c.Challenge()
			if err != nil {
				t.Fatalf("Challenge() error = %v", err)
			}
			if len(challenge) != 16 {
				t.Fatalf("Challenge() length = %d, want 16", len(challenge))
			}
			response := c.Respond(challenge)
			if tt.mutate != nil {
				challenge, response = tt.mutate(challenge, response)
			}

			if got := c.Verify(challenge, response); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallengeRespondVerifyDisabled(t *testing.T) {
	c := mustNew(t, "")

	challenge, err := c.Challenge()
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	if challenge != nil {
		t.Errorf("Challenge() = %v, want nil when disabled", challenge)
	}
	if rsp := c.Respond([]byte("anything")); rsp != nil {
		t.Errorf("Respond() = %v, want nil when disabled", rsp)
	}
	if c.Verify([]byte("anything"), make([]byte, 32)) {
		t.Error("Verify() = true, want false when disabled")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	right := mustNew(t, "correct-key")
	wrong := mustNew(t, "wrong-key")

	challenge, err := right.Challenge()
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	response := wrong.Respond(challenge)

	if right.Verify(challenge, response) {
		t.Error("Verify() accepted a response computed with the wrong key")
	}
}
