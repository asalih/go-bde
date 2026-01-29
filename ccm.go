package bde

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var (
	errCCMInvalidNonceLen = errors.New("ccm: invalid nonce length")
	errCCMInvalidTagLen   = errors.New("ccm: invalid tag length")
	errCCMAuthFailed      = errors.New("ccm: authentication failed")
)

// ccmDecrypt performs AES-CCM decryption with tag verification.
//
// This implementation supports:
// - nonce lengths 7..13 bytes (as per CCM spec)
// - tag lengths 4,6,8,10,12,14,16 (BitLocker uses 16)
// - any plaintext length <= 2^(8L)-1 where L = 15-nonceLen
func ccmDecrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, errCCMInvalidNonceLen
	}
	if len(tag) != 16 && (len(tag) < 4 || len(tag) > 16 || len(tag)%2 != 0) {
		return nil, errCCMInvalidTagLen
	}
	L := 15 - len(nonce)
	if L < 2 || L > 8 {
		return nil, errCCMInvalidNonceLen
	}
	if uint64(len(ciphertext)) >= (uint64(1) << (8 * uint(L))) {
		return nil, errors.New("ccm: message too large")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// CTR decrypt.
	plain := make([]byte, len(ciphertext))
	s0 := make([]byte, 16)
	{
		a0 := make([]byte, 16)
		a0[0] = byte(L - 1)
		copy(a0[1:1+len(nonce)], nonce)
		// counter = 0
		block.Encrypt(s0, a0)

		ctrBlock := make([]byte, 16)
		stream := cipher.NewCTR(block, makeCCMIV(nonce, L, 1, ctrBlock))
		stream.XORKeyStream(plain, ciphertext)
	}

	// Compute authentication tag over AAD and plaintext.
	mac := ccmMac(block, nonce, aad, plain, len(tag))

	// Tag = mac XOR S0 (truncated).
	for i := 0; i < len(tag); i++ {
		mac[i] ^= s0[i]
	}

	if subtle.ConstantTimeCompare(mac[:len(tag)], tag) != 1 {
		return nil, errCCMAuthFailed
	}
	return plain, nil
}

func makeCCMIV(nonce []byte, L int, counter uint32, out []byte) []byte {
	// out must be 16 bytes.
	for i := range out {
		out[i] = 0
	}
	out[0] = byte(L - 1)
	copy(out[1:1+len(nonce)], nonce)
	// Counter is encoded in the last L bytes, big-endian.
	switch L {
	case 2:
		binary.BigEndian.PutUint16(out[14:16], uint16(counter))
	case 3:
		out[13] = byte(counter >> 16)
		out[14] = byte(counter >> 8)
		out[15] = byte(counter)
	case 4:
		binary.BigEndian.PutUint32(out[12:16], counter)
	default:
		// Generic.
		for i := 0; i < L; i++ {
			out[16-L+i] = byte(counter >> (8 * uint(L-1-i)))
		}
	}
	return out
}

func ccmMac(block cipher.Block, nonce, aad, plaintext []byte, tagLen int) []byte {
	L := 15 - len(nonce)
	b0 := make([]byte, 16)
	flags := byte(L - 1)
	if len(aad) > 0 {
		flags |= 1 << 6
	}
	flags |= byte(((tagLen - 2) / 2) << 3)
	b0[0] = flags
	copy(b0[1:1+len(nonce)], nonce)
	// Q = message length in last L bytes, big-endian
	msgLen := uint64(len(plaintext))
	for i := 0; i < L; i++ {
		b0[16-L+i] = byte(msgLen >> (8 * uint(L-1-i)))
	}

	x := make([]byte, 16) // X_i
	// X_1 = E(K, X_0 XOR B_0), with X_0=0
	block.Encrypt(x, b0)

	// AAD
	if len(aad) > 0 {
		buf := formatAAD(aad)
		ccmCbcMacUpdate(block, x, buf)
	}

	// plaintext blocks
	ccmCbcMacUpdate(block, x, plaintext)

	// Return T = MSB(tagLen, X_last)
	out := make([]byte, 16)
	copy(out, x)
	return out
}

func formatAAD(aad []byte) []byte {
	// For AAD length < 2^16 - 2^8: encode as 2-byte big-endian length.
	// (Sufficient for BitLocker usage here.)
	n := len(aad)
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(n))
	buf := make([]byte, 0, 2+n+16)
	buf = append(buf, hdr...)
	buf = append(buf, aad...)
	// Pad to 16-byte multiple.
	if rem := len(buf) % 16; rem != 0 {
		buf = append(buf, make([]byte, 16-rem)...)
	}
	return buf
}

func ccmCbcMacUpdate(block cipher.Block, x []byte, data []byte) {
	tmp := make([]byte, 16)
	for len(data) > 0 {
		n := 16
		if len(data) < 16 {
			n = len(data)
		}
		for i := 0; i < 16; i++ {
			tmp[i] = 0
		}
		copy(tmp[:n], data[:n])
		for i := 0; i < 16; i++ {
			tmp[i] ^= x[i]
		}
		block.Encrypt(x, tmp)
		if len(data) <= 16 {
			break
		}
		data = data[16:]
	}
}

