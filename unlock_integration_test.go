package bde

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
)

// Optional integration test that attempts to unlock a real BitLocker partition using a recovery password.
//
// Env vars:
// - GO_BDE_TEST_DISK_IMAGE: path to disk image
// - GO_BDE_TEST_RECOVERY_PASSWORD_FILE: path to file containing recovery password (e.g. 111111-...)
func TestUnlockWithRecoveryPassword_Image(t *testing.T) {
	imgPath := os.Getenv("GO_BDE_TEST_DISK_IMAGE")
	keyPath := os.Getenv("GO_BDE_TEST_RECOVERY_PASSWORD_FILE")
	if imgPath == "" || keyPath == "" {
		t.Skip("set GO_BDE_TEST_DISK_IMAGE and GO_BDE_TEST_RECOVERY_PASSWORD_FILE to run")
	}

	pwBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	pw := strings.TrimSpace(string(pwBytes))
	if pw == "" {
		t.Fatalf("empty recovery password")
	}

	// Reuse the partition discovery from detect_test.go via the debug test helper:
	// open disk, locate GPT/MBR partitions, pick the BitLocker-marked one.
	f, err := os.Open(imgPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	const blockSize = int64(512)
	parts, err := readDiskPartitions(f, st.Size(), blockSize)
	if err != nil {
		t.Fatalf("read partitions: %v", err)
	}

	var partR *os.File
	_ = partR
	for _, p := range parts {
		startBytes := p.startLBA * blockSize
		sizeBytes := p.sizeLBA * blockSize
		if sizeBytes <= 0 {
			continue
		}

		sr := io.NewSectionReader(f, startBytes, sizeBytes)
		marker, err := HasBitLockerBootSectorMarker(sr)
		if err != nil || !marker {
			continue
		}

		vol, err := New(sr, 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Logf("volume header mapping: sectors=%d offset=%d", vol.information.blockHeader.VolumeHeaderSectors, vol.information.blockHeader.VolumeHeaderOff)
		if vol.information.blockHeader.VolumeHeaderOff > 0 {
			var raw16 [16]byte
			_, _ = sr.ReadAt(raw16[:], int64(vol.information.blockHeader.VolumeHeaderOff))
			t.Logf("ciphertext at volumeHeaderOff[0:16]=%x", raw16[:])
		}

		t.Logf("dataset: size=%d start=%d end=%d fvekType=0x%04x datums=%d",
			vol.information.dataset.header.MetadataSize,
			vol.information.dataset.header.HeaderSize,
			vol.information.dataset.header.MetadataSizeCopy,
			vol.information.dataset.header.EncryptionMethod,
			len(vol.information.dataset.data),
		)
		if len(vol.information.dataset.buf) >= 128 {
			t.Logf("dataset head128=%x", vol.information.dataset.buf[:128])
		}
		if len(vol.information.dataset.data) > 0 {
			d0 := vol.information.dataset.data[0]
			t.Logf("datum0: size=%d role=0x%04x type=0x%04x flags=0x%04x",
				d0.header.Size, d0.header.Role, d0.header.Type, d0.header.Flags)
		}

		// Heuristic: find potential VMK datums (role=0x0002,type=0x0008) within raw dataset buffer.
		needle := []byte{0x02, 0x00, 0x08, 0x00}
		if idx := bytes.Index(vol.information.dataset.buf, needle); idx >= 2 {
			t.Logf("found potential VMK marker at dataset offset=%d (size field=%d)", idx-2, binary.LittleEndian.Uint16(vol.information.dataset.buf[idx-2:idx]))
		} else {
			t.Logf("did not find VMK marker bytes in dataset buffer")
		}

		t.Logf("VMKs: recovery=%d passphrase=%d external=%d",
			len(vol.information.dataset.FindRecoveryVmk()),
			len(vol.information.dataset.FindPassphraseVmk()),
			len(vol.information.dataset.FindExternalVmk()),
		)
		allVMKs := vol.information.dataset.FindDatum(FveDatumRoleVolumeMasterKeyInfo, FveDatumTypeVolumeMasterKeyInfo)
		t.Logf("VMKs total=%d", len(allVMKs))
		for i := 0; i < len(allVMKs) && i < 5; i++ {
			if vi, ok := allVMKs[i].GetVmkInfo(); ok {
				t.Logf("VMK[%d] protectorType=0x%04x guid=%x", i, vi.ProtectorType, vi.GuidIdentifier)
			}
		}

		if err := vol.UnlockWithRecoveryPassword(pw, ""); err != nil {
			t.Fatalf("UnlockWithRecoveryPassword: %v", err)
		}
		t.Logf("unlocked: fvekLen=%d fvekType=0x%04x", len(vol.fvek), vol.fvekType)

		stream, err := vol.Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		// Read first 512 bytes from decrypted view; for NTFS volumes it usually starts with an x86 jump.
		buf := make([]byte, 512)
		if _, err := stream.ReadAt(buf, 0); err != nil {
			t.Fatalf("ReadAt: %v", err)
		}
		t.Logf("decrypted[0:16]=%x", buf[:16])
		if len(buf) >= 11 && string(buf[3:11]) != "NTFS    " {
			t.Fatalf("expected NTFS signature at [3:11], got %q (boot jump=%x)", string(buf[3:11]), buf[:3])
		}
		return
	}

	t.Fatalf("no BitLocker partition found")
}

