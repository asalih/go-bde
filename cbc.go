package bde

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

var errCBCInvalidKeyLen = errors.New("cbc: invalid key length")

// cbcCipher implements BitLocker AES-CBC sector decryption (no diffuser).
//
// BitLocker derives the CBC IV as:
//
//	IV = AES-ECB_encrypt(key=FVEK, plaintext=LE128(sector_offset_bytes))
//
// Sector data is then encrypted/decrypted with AES-CBC using that IV.
type cbcCipher struct {
	block      cipherBlock
	sectorSize int
}

func newCBCCipher(fvek []byte, sectorSize int) (*cbcCipher, error) {
	if len(fvek) != 16 && len(fvek) != 32 {
		return nil, errCBCInvalidKeyLen
	}
	if sectorSize <= 0 || sectorSize%16 != 0 {
		return nil, errors.New("cbc: invalid sector size")
	}
	b, err := aes.NewCipher(fvek)
	if err != nil {
		return nil, err
	}
	return &cbcCipher{block: b, sectorSize: sectorSize}, nil
}

func (c *cbcCipher) decryptSector(dst, src []byte, sectorNum uint64) {
	if len(dst) != len(src) || len(dst)%16 != 0 {
		panic("cbc: invalid sector length")
	}
	if len(dst) != c.sectorSize {
		panic("cbc: unexpected sector size")
	}

	// Compute IV = AES-ECB(key, LE128(sector_offset_bytes))
	var ivPlain [16]byte
	sectorOffsetBytes := sectorNum * uint64(c.sectorSize)
	binary.LittleEndian.PutUint64(ivPlain[:8], sectorOffsetBytes)

	var iv [16]byte
	c.block.Encrypt(iv[:], ivPlain[:])

	// Manual CBC decrypt:
	// P_i = D_k(C_i) xor C_{i-1}, with C_{-1} = IV
	prev := iv
	var dec [16]byte
	var ctCopy [16]byte

	for off := 0; off < len(src); off += 16 {
		copy(ctCopy[:], src[off:off+16])
		c.block.Decrypt(dec[:], ctCopy[:])
		for i := 0; i < 16; i++ {
			dst[off+i] = dec[i] ^ prev[i]
		}
		prev = ctCopy
	}
}
