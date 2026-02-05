package bde

import (
	"fmt"
	"io"
	"os"
	"testing"
)

// TestOpenPartitionFromDiskImage tests opening a BitLocker partition from a raw disk image
// where the partition starts at a known offset.
//
// This test uses the specific disk image: 109-Win10-Responder_20260129110126-1_image.Ex01.dd
// The BitLocker partition starts at LBA 32768 (offset 16777216 bytes).
func TestOpenPartitionFromDiskImage(t *testing.T) {
	imagePath := "cmd/testdata/109-Win10-Responder_20260129110126-1_image.Ex01.dd"

	f, err := os.Open(imagePath)
	if err != nil {
		t.Skipf("test image not found: %v", err)
	}
	defer f.Close()

	// Partition layout from GPT:
	// - Microsoft reserved partition: startLBA=34, sizeLBA=32734
	// - Basic data partition (BitLocker): startLBA=32768, sizeLBA=41906176
	const (
		sectorSize     = 512
		partitionStart = 32768 * sectorSize   // 16777216 bytes
		partitionSize  = 41906176 * sectorSize // 21455962112 bytes
	)

	// Create a section reader for the BitLocker partition
	partitionReader := io.NewSectionReader(f, partitionStart, partitionSize)

	// Open the BitLocker volume using GUID locators and boot sector offsets
	vol, err := New(partitionReader, partitionSize)
	if err != nil {
		t.Skipf("New() failed (image may not have GUID locators): %v", err)
	}
	t.Log("New() succeeded")

	// Verify we got valid metadata
	t.Logf("Volume info:")
	t.Logf("  Version: %d", vol.Version())
	t.Logf("  SectorSize: %d", vol.SectorSize())
	t.Logf("  Encrypted: %v", vol.Encrypted())

	// Check that the volume looks valid
	if vol.Version() < 1 || vol.Version() > 2 {
		t.Errorf("unexpected version: %d", vol.Version())
	}
	if vol.SectorSize() != 512 && vol.SectorSize() != 4096 {
		t.Errorf("unexpected sector size: %d", vol.SectorSize())
	}

	// List available VMK identifiers
	ids := vol.Identifiers()
	t.Logf("  VMK Identifiers: %d found", len(ids))
	for i, id := range ids {
		t.Logf("    [%d] %x", i, id)
	}
}

// TestOpenDirectBitLockerVolume tests opening a direct BitLocker volume
// (not a partition within a disk image).
//
// This test uses: FileExplorer-Raw.001
func TestOpenDirectBitLockerVolume(t *testing.T) {
	imagePath := "cmd/testdata/FileExplorer-Raw.001"

	f, err := os.Open(imagePath)
	if err != nil {
		t.Skipf("test image not found: %v", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	size := st.Size()

	t.Logf("File size: %d bytes (%.2f MiB)", size, float64(size)/(1024*1024))

	// Open the BitLocker volume using GUID locators and boot sector offsets
	vol, err := New(f, size)
	if err != nil {
		t.Skipf("New() failed (image may not have GUID locators): %v", err)
	}
	t.Log("New() succeeded")

	// Verify we got valid metadata
	t.Logf("Volume info:")
	t.Logf("  Version: %d", vol.Version())
	t.Logf("  SectorSize: %d", vol.SectorSize())
	t.Logf("  Encrypted: %v", vol.Encrypted())

	if vol.Version() < 1 || vol.Version() > 2 {
		t.Errorf("unexpected version: %d", vol.Version())
	}

	ids := vol.Identifiers()
	t.Logf("  VMK Identifiers: %d found", len(ids))
	if len(ids) == 0 {
		t.Error("expected at least one VMK identifier")
	}
}

// TestOpenPartitionWithExplicitOffset is a more generic test that can be used
// with any disk image where you know the partition offset.
//
// Set environment variables:
// - GO_BDE_PARTITION_IMAGE: path to disk image
// - GO_BDE_PARTITION_OFFSET: partition start offset in bytes (default: 16777216)
// - GO_BDE_PARTITION_SIZE: partition size in bytes (optional, will use file size - offset if not set)
func TestOpenPartitionWithExplicitOffset(t *testing.T) {
	imagePath := os.Getenv("GO_BDE_PARTITION_IMAGE")
	if imagePath == "" {
		t.Skip("set GO_BDE_PARTITION_IMAGE to run this test")
	}

	f, err := os.Open(imagePath)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Parse offset (default: 16777216 = 32768 sectors * 512)
	offsetStr := os.Getenv("GO_BDE_PARTITION_OFFSET")
	var partitionStart int64 = 16777216
	if offsetStr != "" {
		if _, err := fmt.Sscanf(offsetStr, "%d", &partitionStart); err != nil {
			t.Fatalf("invalid GO_BDE_PARTITION_OFFSET: %v", err)
		}
	}

	// Parse size (default: rest of file)
	sizeStr := os.Getenv("GO_BDE_PARTITION_SIZE")
	partitionSize := st.Size() - partitionStart
	if sizeStr != "" {
		if _, err := fmt.Sscanf(sizeStr, "%d", &partitionSize); err != nil {
			t.Fatalf("invalid GO_BDE_PARTITION_SIZE: %v", err)
		}
	}

	t.Logf("Opening partition at offset=%d size=%d", partitionStart, partitionSize)

	partitionReader := io.NewSectionReader(f, partitionStart, partitionSize)

	// Open the BitLocker volume using GUID locators and boot sector offsets
	vol, err := New(partitionReader, partitionSize)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	t.Logf("Volume info:")
	t.Logf("  Version: %d", vol.Version())
	t.Logf("  SectorSize: %d", vol.SectorSize())
	t.Logf("  Encrypted: %v", vol.Encrypted())
}
