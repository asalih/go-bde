package bde

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// Test vectors from IEEE P1619/D16 Annex B (as referenced by mbedtls test suite).
// We only need decryption for this project, so we validate that decrypting the known ciphertext
// yields the known plaintext for a 512-byte data unit.
func TestXTS_IEEE1619_Vector4_Decrypt(t *testing.T) {
	// Combined 256-bit key = key1||key2 (AES-128-XTS).
	key := mustHex(t, "2718281828459045235360287471352631415926535897932384626433832795")
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
	tweak := mustHex(t, "00000000000000000000000000000000")
	if len(tweak) != 16 {
		t.Fatalf("expected 16-byte tweak, got %d", len(tweak))
	}

	plaintext := mustHex(t,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
			"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" +
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
			"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ciphertext := mustHex(t,
		"27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c" +
			"c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412" +
			"328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce" +
			"93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265" +
			"5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8" +
			"a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434" +
			"1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c" +
			"5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e" +
			"94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc" +
			"1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3" +
			"e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344" +
			"b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd" +
			"74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752" +
			"afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e" +
			"bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d" +
			"eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568")

	if len(plaintext) != 512 || len(ciphertext) != 512 {
		t.Fatalf("expected 512-byte data unit, got pt=%d ct=%d", len(plaintext), len(ciphertext))
	}

	c, err := newXTSCipher(key)
	if err != nil {
		t.Fatalf("newXTSCipher: %v", err)
	}

	var sectorNum uint64 // tweak is 0
	out := make([]byte, 512)
	c.decryptSector(out, ciphertext, sectorNum)
	if hex.EncodeToString(out) != hex.EncodeToString(plaintext) {
		t.Fatalf("XTS decrypt mismatch (first16 got=%x want=%x)", out[:16], plaintext[:16])
	}
}

