package bde

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"sync"
)

var errXTSInvalidKeyLen = errors.New("xts: invalid key length")

var sectorBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096) // enough for 512/4096 sector sizes
		return &b
	},
}

type xtsCipher struct {
	dataKey  cipherBlock
	tweakKey cipherBlock
}

type cipherBlock interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

func newXTSCipher(fvek []byte) (*xtsCipher, error) {
	if len(fvek) != 32 && len(fvek) != 64 {
		return nil, errXTSInvalidKeyLen
	}
	half := len(fvek) / 2
	// XTS key is key1||key2 where key1 is the data key and key2 is the tweak key.
	b1, err := aes.NewCipher(fvek[:half])
	if err != nil {
		return nil, err
	}
	b2, err := aes.NewCipher(fvek[half:])
	if err != nil {
		return nil, err
	}
	return &xtsCipher{dataKey: b1, tweakKey: b2}, nil
}

func (c *xtsCipher) decryptSector(dst, src []byte, sectorNum uint64) {
	// Sector sizes in BitLocker are multiples of 16 (512/4096).
	// This implementation does not support ciphertext stealing.
	if len(dst) != len(src) || len(dst)%16 != 0 {
		panic("xts: invalid sector length")
	}

	tweak := make([]byte, 16)
	// BitLocker uses the data unit number (sector index) as tweak input.
	// Use little-endian uint64 in the first 8 bytes (common for disk encryption).
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)

	c.tweakKey.Encrypt(tweak, tweak)

	tmp := make([]byte, 16)
	for off := 0; off < len(src); off += 16 {
		// PP = C xor tweak
		for i := 0; i < 16; i++ {
			tmp[i] = src[off+i] ^ tweak[i]
		}
		// P' = D_k1(PP)
		c.dataKey.Decrypt(tmp, tmp)
		// P = P' xor tweak
		for i := 0; i < 16; i++ {
			dst[off+i] = tmp[i] ^ tweak[i]
		}
		gfMulX(tweak)
	}
}

func gfMulX(tweak []byte) {
	// XTS tweak is treated as a 128-bit little-endian value for GF(2^128) multiply-by-x
	// in disk encryption usage. Apply the 0x87 reduction constant to the low byte.
	var carry byte
	for i := 0; i < 16; i++ {
		b := tweak[i]
		newCarry := b >> 7
		tweak[i] = (b << 1) | carry
		carry = newCarry
	}
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}

