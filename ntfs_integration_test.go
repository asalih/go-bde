//go:build ntfs

package bde

import (
	"io"
	"os"
	"strings"
	"testing"

	ntfs "github.com/asalih/go-ntfs/parser"
)

// Integration test: unlock BitLocker and parse NTFS using github.com/asalih/go-ntfs.
//
// Run:
//   GO_BDE_TEST_DISK_IMAGE=... GO_BDE_TEST_RECOVERY_PASSWORD_FILE=... go test ./... -tags ntfs -run TestUnlockAndReadNTFS_Image -v
func TestUnlockAndReadNTFS_Image(t *testing.T) {
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

		vol, err := New(sr)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := vol.UnlockWithRecoveryPassword(pw, ""); err != nil {
			t.Fatalf("UnlockWithRecoveryPassword: %v", err)
		}
		stream, err := vol.Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		ctx, err := ntfs.GetNTFSContext(stream, 0)
		if err != nil {
			t.Fatalf("ntfs.GetNTFSContext: %v", err)
		}
		root, err := ctx.GetMFT(5)
		if err != nil {
			t.Fatalf("ntfs root MFT: %v", err)
		}
		infos := ntfs.ListDir(ctx, root)
		if len(infos) == 0 {
			t.Fatalf("ntfs.ListDir returned 0 entries")
		}
		t.Logf("ntfs: listed %d entries in root", len(infos))
		return
	}

	t.Fatalf("no BitLocker partition found")
}

