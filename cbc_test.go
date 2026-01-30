package bde

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestCBCDecryptSector_RoundTrip(t *testing.T) {
	const sectorSize = 512
	// AES-128 key (16 bytes).
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	sectorNum := uint64(12345)

	plain := make([]byte, sectorSize)
	for i := range plain {
		plain[i] = byte(i)
	}

	// Encrypt using the BitLocker CBC IV scheme but standard library CBC for blocks.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	var ivPlain [16]byte
	binary.LittleEndian.PutUint64(ivPlain[:8], sectorNum*sectorSize)
	var iv [16]byte
	block.Encrypt(iv[:], ivPlain[:])

	enc := cipher.NewCBCEncrypter(block, iv[:])
	ciphertext := make([]byte, sectorSize)
	enc.CryptBlocks(ciphertext, plain)

	cbc, err := newCBCCipher(key, sectorSize)
	if err != nil {
		t.Fatalf("newCBCCipher: %v", err)
	}
	out := make([]byte, sectorSize)
	cbc.decryptSector(out, ciphertext, sectorNum)

	if !bytes.Equal(out, plain) {
		t.Fatalf("cbc decrypt mismatch: got=%x want=%x", out[:32], plain[:32])
	}
}
