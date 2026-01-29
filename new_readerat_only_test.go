package bde

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type readerAtOnly struct {
	b []byte
}

func (r *readerAtOnly) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.EOF
	}
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestNew_WorksWithoutSizeMethod_UsingSignatureScan(t *testing.T) {
	// Build a small synthetic "partition" that:
	// - has BitLocker OEM marker in the boot sector
	// - has a valid Information block + dataset at a later offset
	const (
		totalSize     = 2 << 20 // 2 MiB
		infoOffset    = 1 << 20 // 1 MiB
		datasetSize   = 512
	)

	buf := make([]byte, totalSize)

	// Boot sector.
	var bs BootSector
	copy(bs.Jump[:], []byte{0xEB, 0x58, 0x90})
	copy(bs.Oem[:], BITLOCKER_SIGNATURE)
	bs.Bpb.BytesPerSector = 512
	bs.Bpb.SectorsPerCluster = 8
	{
		var boot bytes.Buffer
		if err := binary.Write(&boot, binary.LittleEndian, &bs); err != nil {
			t.Fatalf("write boot: %v", err)
		}
		copy(buf[:boot.Len()], boot.Bytes())
	}

	// Metadata block header + metadata header at infoOffset.
	{
		bh := FveMetadataBlockHeaderV2{}
		copy(bh.Signature[:], BITLOCKER_SIGNATURE)
		bh.Version = 2
		// Minimal, for parsing purposes.
		bh.MetadataOffset1 = uint64(infoOffset)

		var hb bytes.Buffer
		if err := binary.Write(&hb, binary.LittleEndian, &bh); err != nil {
			t.Fatalf("write block header: %v", err)
		}
		copy(buf[infoOffset:infoOffset+hb.Len()], hb.Bytes())

		mh := FveMetadataHeader{}
		mh.MetadataSize = datasetSize
		mh.Version = 1
		mh.HeaderSize = uint32(binary.Size(FveMetadataHeader{}))
		mh.MetadataSizeCopy = mh.MetadataSize
		mh.EncryptionMethod = uint32(FveKeyTypeAesXts256)

		var mb bytes.Buffer
		if err := binary.Write(&mb, binary.LittleEndian, &mh); err != nil {
			t.Fatalf("write metadata header: %v", err)
		}
		copy(buf[infoOffset+64:infoOffset+64+mb.Len()], mb.Bytes())
	}

	r := &readerAtOnly{b: buf}
	vol, err := New(r)
	if err != nil {
		t.Fatalf("expected New() to succeed without Size(); got err=%v", err)
	}
	if vol.Version() != 1 {
		t.Fatalf("expected metadata header version=1, got %d", vol.Version())
	}
	if vol.SectorSize() != 512 {
		t.Fatalf("expected sectorSize=512, got %d", vol.SectorSize())
	}
}

