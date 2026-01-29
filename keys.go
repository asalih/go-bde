package bde

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Stretch implements BitLocker's key stretching algorithm.
func Stretch(password []byte, salt []byte, rounds int) ([]byte, error) {
	if len(password) != 32 {
		return nil, errors.New("invalid password length")
	}

	if len(salt) != 16 {
		return nil, errors.New("invalid salt length")
	}

	if rounds == 0 {
		rounds = 0x100000 // default rounds
	}

	// Layout: chained hash | user hash | salt | counter
	// SHA256 digest is 32 bytes, salt is 16 bytes, counter is 8 bytes (uint64).
	data := make([]byte, 32+32+16+8)

	// Copy user hash.
	copy(data[32:64], password)

	// Copy salt.
	copy(data[64:80], salt)

	// Apply rounds.
	for i := 0; i < rounds; i++ {
		// Update counter.
		binary.LittleEndian.PutUint64(data[80:88], uint64(i))

		// Hash and copy to output buffer.
		h := sha256.Sum256(data)
		copy(data[:32], h[:])
	}

	// Return final digest.
	result := make([]byte, 32)
	copy(result, data[:32])
	return result, nil
}

// DeriveUserKey derives an AES key from a user passphrase.
func DeriveUserKey(userPassword string) []byte {
	// Convert to UTF-16LE.
	utf16Encoded := UTF16LEEncode(userPassword)

	// First hash.
	firstHash := sha256.Sum256(utf16Encoded)

	// Second hash.
	secondHash := sha256.Sum256(firstHash[:])

	return secondHash[:]
}

// DeriveRecoveryKey derives an AES key from a BitLocker recovery password.
func DeriveRecoveryKey(recoveryPassword string) ([]byte, error) {
	if err := CheckRecoveryPassword(recoveryPassword); err != nil {
		return nil, err
	}

	blocks := strings.Split(recoveryPassword, "-")
	key := make([]byte, 16) // 8 blocks x 2 bytes = 16 bytes

	for i, block := range blocks {
		blockValue, _ := strconv.Atoi(block)
		blockValue = blockValue / 11 // divide by 11

		// Put as little-endian uint16.
		binary.LittleEndian.PutUint16(key[i*2:i*2+2], uint16(blockValue))
	}

	// Compute SHA256.
	hash := sha256.Sum256(key)
	return hash[:], nil
}

// CheckRecoveryPassword validates a BitLocker recovery password format.
func CheckRecoveryPassword(recoveryPassword string) error {
	blocks := strings.Split(recoveryPassword, "-")
	if len(blocks) != 8 {
		return errors.New("invalid recovery password: invalid length")
	}

	for _, block := range blocks {
		// Must be numeric.
		blockValue, err := strconv.Atoi(block)
		if err != nil {
			return errors.New("invalid recovery password: contains non-numeric characters")
		}

		// Must be divisible by 11.
		if blockValue%11 != 0 {
			return errors.New("invalid recovery password: block is not divisible by 11")
		}

		// Maximum check.
		if blockValue >= 720896 { // 2^16 * 11
			return errors.New("invalid recovery password: block is >= 720896 (2^16 * 11)")
		}

		// Check checksum digit.
		digits := make([]int, len(block))
		for i, c := range block {
			digits[i], _ = strconv.Atoi(string(c))
		}

		if len(digits) != 6 {
			return errors.New("invalid recovery password: each block must be 6 digits")
		}

		checksum := (digits[0] - digits[1] + digits[2] - digits[3] + digits[4]) % 11
		if checksum != digits[5] {
			return errors.New("invalid recovery password: invalid block checksum")
		}
	}

	return nil
}

// UTF16LEEncode converts a UTF-8 string to UTF-16LE (required by BitLocker).
func UTF16LEEncode(s string) []byte {
	runes := []rune(s)
	utf16Encoded := utf16.Encode(runes)
	bytes := make([]byte, len(utf16Encoded)*2)

	for i, utf16Value := range utf16Encoded {
		binary.LittleEndian.PutUint16(bytes[i*2:i*2+2], utf16Value)
	}

	return bytes
}
