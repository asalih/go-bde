package bde

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"unicode/utf16"
)

func TestHasBitLockerBootSectorMarker(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf[0:3], []byte{0xEB, 0x58, 0x90}) // typical boot jump + NOP
	copy(buf[3:11], BITLOCKER_SIGNATURE)     // OEM field starts at offset 3

	ok, err := HasBitLockerBootSectorMarker(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected marker to be detected")
	}
}

func TestIsBitLockerVolume_DetectsViaGuidLocatorAndInformationSignature(t *testing.T) {
	// Create a tiny synthetic image:
	// - boot sector at 0 with sector size shift set to 512 (9)
	// - a GUID locator block in sector 0 that points to an Information block at offset 4096
	// - an Information block signature "-FVE-FS-" at that offset
	const sectorSize = 512
	const infoOffset = 4096
	img := make([]byte, infoOffset+sectorSize)

	// Write a plausible boot sector to allow deriveSectorSize() to work.
	var bs BootSector
	bs.BytesPerSectorShift = 9
	bs.SectorsPerClusterShift = 0
	var boot bytes.Buffer
	if err := binary.Write(&boot, binary.LittleEndian, &bs); err != nil {
		t.Fatalf("failed to build boot sector: %v", err)
	}
	copy(img[:boot.Len()], boot.Bytes())

	// Put GUID locator in sector 0.
	copy(img[0:16], INFORMATION_OFFSET_GUID[:])
	binary.LittleEndian.PutUint64(img[16:24], uint64(infoOffset))
	// other 2 offsets are 0.

	// Put Information block signature at infoOffset.
	copy(img[infoOffset:infoOffset+8], BITLOCKER_SIGNATURE)

	ok, err := IsBitLockerVolumeWithOptions(bytes.NewReader(img), ProbeOptions{
		SectorSize:               512,
		MaxSectors:               1,
		AcceptSignatureAtOffset0: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected volume to be detected as BitLocker")
	}
}

// Optional integration test.
//
// Set GO_BDE_TEST_DISK_IMAGE to a disk image path. The test will:
// - parse GPT and/or MBR partitions
// - create a section reader for each partition
// - detect BitLocker partitions
// - try bde.New() on the BitLocker partition
func TestDiskImagePartitions_FindAndParseBitLocker(t *testing.T) {

	path := os.Getenv("GO_BDE_TEST_DISK_IMAGE")
	if path == "" {
		t.Skip("set GO_BDE_TEST_DISK_IMAGE to run this test")
	}

	f, err := os.Open(path)
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
	if len(parts) == 0 {
		t.Fatalf("no partitions found")
	}

	for _, p := range parts {
		t.Logf("partition: kind=%s name=%q type=%s startLBA=%d sizeLBA=%d", p.kind, p.name, p.typ, p.startLBA, p.sizeLBA)
	}

	foundBitLocker := false
	var lastParseErr error
	for _, p := range parts {
		startBytes := p.startLBA * blockSize
		sizeBytes := p.sizeLBA * blockSize
		if sizeBytes <= 0 {
			continue
		}
		sr := io.NewSectionReader(f, startBytes, sizeBytes)

		marker, markerErr := HasBitLockerBootSectorMarker(sr)
		if markerErr != nil {
			t.Logf("partition %s: marker check error: %v", p.label(), markerErr)
		}
		vol, volErr := IsBitLockerVolume(sr)
		if volErr != nil {
			t.Logf("partition %s: IsBitLockerVolume error: %v", p.label(), volErr)
		}

		if !(marker || vol) {
			continue
		}
		foundBitLocker = true

		// Try parsing with the library.
		b, err := New(sr)
		if err != nil {
			// Extra debug: parse boot sector fields and locator scan results.
			var bs BootSector
			if err2 := binary.Read(io.NewSectionReader(sr, 0, 4096), binary.LittleEndian, &bs); err2 == nil {
				t.Logf("partition %s: BPB bytesPerSector=%d sectorsPerCluster=%d informationLcn=%d bytesPerSectorShift=%d sectorsPerClusterShift=%d",
					p.label(),
					bs.Bpb.BytesPerSector, bs.Bpb.SectorsPerCluster,
					bs.InformationLcn,
					bs.BytesPerSectorShift, bs.SectorsPerClusterShift,
				)
			}
			{
				var boot [512]byte
				if _, err2 := sr.ReadAt(boot[:], 0); err2 == nil {
					u16 := func(off int) uint16 { return binary.LittleEndian.Uint16(boot[off : off+2]) }
					u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(boot[off : off+4]) }
					u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(boot[off : off+8]) }

					t.Logf("partition %s: boot OEM=%q bytesPerSector=%d sectorsPerCluster=%d hiddenSectors=%d",
						p.label(),
						string(boot[3:11]),
						u16(0x0B),
						boot[0x0D],
						u32(0x1C),
					)
					t.Logf("partition %s: boot u64@0x28=%d u64@0x30=%d u64@0x38=%d u64@0x40=%d",
						p.label(),
						u64(0x28), u64(0x30), u64(0x38), u64(0x40),
					)

					// Try interpreting some NTFS-like fields as LCNs pointing to metadata.
					clusterSize := int64(u16(0x0B)) * int64(boot[0x0D])
					for _, c := range []struct {
						name string
						val  uint64
					}{
						{"u64@0x30", u64(0x30)},
						{"u64@0x38", u64(0x38)},
						{"u64@0x40", u64(0x40)},
					} {
						if c.val == 0 || clusterSize <= 0 {
							continue
						}
						off := int64(c.val) * clusterSize
						var sig [8]byte
						if _, err3 := sr.ReadAt(sig[:], off); err3 == nil {
							t.Logf("partition %s: at %s*clusterSize => offset=%d signature=%q", p.label(), c.name, off, string(sig[:]))
						}
						if _, err3 := NewInformation(sr, off); err3 == nil {
							t.Logf("partition %s: NewInformation succeeded at %s-derived offset=%d", p.label(), c.name, off)
						} else {
							t.Logf("partition %s: NewInformation failed at %s-derived offset=%d: %v", p.label(), c.name, off, err3)
						}
					}
				}
			}
			if br, err2 := NewBootSectorReader(sr); err2 == nil {
				t.Logf("partition %s: computed sectorSize=%d clusterSize=%d infoOffsets=%v eowOffsets=%v",
					p.label(), br.SectorSize(), br.ClusterSize(), br.InformationOffsets(), br.EowOffsets())
			}

			// Search for known GUID locator patterns in the front/back windows.
			if sz, ok := readerSize(sr); ok && sz > 0 {
				t.Logf("partition %s: startBytes=%d sizeBytes=%d", p.label(), startBytes, sizeBytes)
				sigOffs, _ := findSignatureOffsets(sr, sz, BITLOCKER_SIGNATURE)
				if len(sigOffs) > 0 {
					t.Logf("partition %s: found BITLOCKER_SIGNATURE at offsets (showing up to 10): %v", p.label(), sigOffs[:minInt(10, len(sigOffs))])
				} else {
					t.Logf("partition %s: did not find BITLOCKER_SIGNATURE in front/back scan windows", p.label())
				}

				for _, pat := range []struct {
					name string
					b    []byte
				}{
					{"INFO_GUID_LE", INFORMATION_OFFSET_GUID[:]},
					{"INFO_GUID_RFC", INFORMATION_OFFSET_GUID_RFC4122[:]},
					{"EOW_GUID_LE", EOW_INFORMATION_OFFSET_GUID[:]},
					{"EOW_GUID_RFC", EOW_INFORMATION_OFFSET_GUID_RFC4122[:]},
				} {
					offs, _ := findSignatureOffsets(sr, sz, pat.b)
					if len(offs) > 0 {
						t.Logf("partition %s: found %s at offsets (showing up to 5): %v", p.label(), pat.name, offs[:minInt(5, len(offs))])
					} else {
						t.Logf("partition %s: did not find %s in front/back scan windows", p.label(), pat.name)
					}
				}

				// Sample a few bytes near the end of the partition for quick visibility.
				for _, d := range []int64{4096, 65536, 1 << 20, 8 << 20} {
					if sz <= d {
						continue
					}
					off := sz - d
					var tail [64]byte
					if _, err2 := sr.ReadAt(tail[:], off); err2 == nil {
						t.Logf("partition %s: bytes at (size-%d) offset=%d head64=%x", p.label(), d, off, tail[:])
					}
				}

				// Optional: full scan for signature occurrences and attempt to parse them.
				if os.Getenv("GO_BDE_DEBUG_FULLSCAN") == "1" {
					offs, _ := findSignatureOffsetsFull(sr, sz, BITLOCKER_SIGNATURE, 10)
					t.Logf("partition %s: full-scan BITLOCKER_SIGNATURE occurrences (up to 10): %v", p.label(), offs)
					for _, off := range offs {
						var head [64]byte
						_, _ = sr.ReadAt(head[:], off)
						t.Logf("partition %s: at signature offset=%d head64=%x", p.label(), off, head[:])
						// Parse metadata block header + metadata header for debugging.
						var bh FveMetadataBlockHeaderV2
						if err3 := binary.Read(io.NewSectionReader(sr, off, 1024), binary.LittleEndian, &bh); err3 == nil {
							t.Logf("partition %s: parsed block header at %d: version=%d metaOffsets=[%d %d %d] volumeHeaderSectors=%d volumeHeaderOff=%d",
								p.label(),
								off,
								bh.Version,
								bh.MetadataOffset1, bh.MetadataOffset2, bh.MetadataOffset3,
								bh.VolumeHeaderSectors, bh.VolumeHeaderOff,
							)
							var mh FveMetadataHeader
							if err4 := binary.Read(io.NewSectionReader(sr, off+64, 1024), binary.LittleEndian, &mh); err4 == nil {
								t.Logf("partition %s: parsed metadata header at %d: size=%d version=%d headerSize=%d encMethod=0x%08x",
									p.label(),
									off+64,
									mh.MetadataSize, mh.Version, mh.HeaderSize, mh.EncryptionMethod,
								)
							} else {
								t.Logf("partition %s: failed to parse metadata header at %d: %v", p.label(), off+64, err4)
							}
						} else {
							t.Logf("partition %s: failed to parse metadata block header at %d: %v", p.label(), off, err3)
						}
						if info, err2 := NewInformation(sr, off); err2 == nil {
							t.Logf("partition %s: NewInformation OK at offset=%d version=%d metaSize=%d", p.label(), off, info.Version(), info.metadataHeader.MetadataSize)
						} else {
							t.Logf("partition %s: NewInformation FAILED at offset=%d: %v", p.label(), off, err2)
						}
					}
				}

				// Optional deep scan for the first occurrence of locator GUIDs across the partition.
				// Enable with GO_BDE_DEBUG_SCAN=1.
				if os.Getenv("GO_BDE_DEBUG_SCAN") == "1" {
					for _, pat := range []struct {
						name string
						b    []byte
					}{
						{"INFO_GUID_LE", INFORMATION_OFFSET_GUID[:]},
						{"INFO_GUID_RFC", INFORMATION_OFFSET_GUID_RFC4122[:]},
						{"EOW_GUID_LE", EOW_INFORMATION_OFFSET_GUID[:]},
						{"EOW_GUID_RFC", EOW_INFORMATION_OFFSET_GUID_RFC4122[:]},
					} {
						if off, ok, _ := findFirstOccurrence(sr, sz, pat.b, 2<<30); ok { // scan up to 2 GiB
							t.Logf("partition %s: deep-scan found %s at offset %d", p.label(), pat.name, off)
						} else {
							t.Logf("partition %s: deep-scan did not find %s within 2 GiB", p.label(), pat.name)
						}
						if off, ok, _ := findFirstOccurrenceTail(sr, sz, pat.b, 2<<30); ok {
							t.Logf("partition %s: tail-scan found %s at offset %d", p.label(), pat.name, off)
						} else {
							t.Logf("partition %s: tail-scan did not find %s within last 2 GiB", p.label(), pat.name)
						}
					}
					if off, ok, _ := findFirstOccurrence(sr, sz, BITLOCKER_SIGNATURE, 2<<30); ok {
						t.Logf("partition %s: deep-scan found BITLOCKER_SIGNATURE at offset %d", p.label(), off)
					} else {
						t.Logf("partition %s: deep-scan did not find BITLOCKER_SIGNATURE within 2 GiB", p.label())
					}
					if off, ok, _ := findFirstOccurrenceTail(sr, sz, BITLOCKER_SIGNATURE, 2<<30); ok {
						t.Logf("partition %s: tail-scan found BITLOCKER_SIGNATURE at offset %d", p.label(), off)
					} else {
						t.Logf("partition %s: tail-scan did not find BITLOCKER_SIGNATURE within last 2 GiB", p.label())
					}
				}
			}

			// Provide a bit of debug context.
			var head [64]byte
			_, _ = sr.ReadAt(head[:], 0)
			t.Logf("partition %s: bde.New failed: %v (head=%x)", p.label(), err, head[:])
			lastParseErr = err
			continue
		}

		t.Logf("partition %s: parsed BitLocker metadata: version=%d sectorSize=%d encrypted=%v",
			p.label(), b.Version(), b.SectorSize(), b.Encrypted())
		return
	}

	if !foundBitLocker {
		t.Fatalf("no BitLocker partition detected (marker/signature)")
	}
	if lastParseErr != nil {
		t.Fatalf("BitLocker-like partition(s) found, but parsing failed; last error: %v", lastParseErr)
	}
	t.Fatalf("BitLocker-like partition(s) found, but parsing failed")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Debug helper: full scan for "-FVE-FS-" across the BitLocker-marked partition.
// Enable with GO_BDE_DEBUG_FULLSCAN=1 and GO_BDE_TEST_DISK_IMAGE set.
func TestDebugFullSignatureScan(t *testing.T) {
	if os.Getenv("GO_BDE_DEBUG_FULLSCAN") != "1" {
		t.Skip("set GO_BDE_DEBUG_FULLSCAN=1 to run this test")
	}
	path := os.Getenv("GO_BDE_TEST_DISK_IMAGE")
	if path == "" {
		t.Skip("set GO_BDE_TEST_DISK_IMAGE to run this test")
	}

	f, err := os.Open(path)
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

		t.Logf("full scan partition %s startBytes=%d sizeBytes=%d", p.label(), startBytes, sizeBytes)
		offsets, err := findSignatureOffsetsFull(sr, sizeBytes, BITLOCKER_SIGNATURE, 20)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		t.Logf("found %d occurrences (showing): %v", len(offsets), offsets)
		for _, off := range offsets {
			var sigPart [8]byte
			var sigDiskAtPart [8]byte
			_, _ = sr.ReadAt(sigPart[:], off)
			_, _ = f.ReadAt(sigDiskAtPart[:], startBytes+off)
			t.Logf("offset=%d sig(partRel)=%q sig(diskAtPart)=%q", off, string(sigPart[:]), string(sigDiskAtPart[:]))
		}
		return
	}

	t.Fatalf("no BitLocker-marked partition found for full scan")
}

func findSignatureOffsetsFull(r io.ReaderAt, size int64, sig []byte, maxHits int) ([]int64, error) {
	if size <= 0 || len(sig) == 0 {
		return nil, nil
	}
	if maxHits <= 0 {
		maxHits = 1
	}
	const chunkSize = int64(64 << 20) // 64 MiB
	buf := make([]byte, chunkSize)
	overlap := int64(len(sig) - 1)
	if overlap < 0 {
		overlap = 0
	}

	out := make([]int64, 0, minInt(maxHits, 64))
	for off := int64(0); off < size; {
		readLen := chunkSize
		if rem := size - off; rem < readLen {
			readLen = rem
		}
		chunk := buf[:readLen]
		if _, err := r.ReadAt(chunk, off); err != nil {
			return out, err
		}
		searchFrom := 0
		for len(out) < maxHits {
			idx := bytes.Index(chunk[searchFrom:], sig)
			if idx < 0 {
				break
			}
			out = append(out, off+int64(searchFrom+idx))
			searchFrom += idx + 1
			if searchFrom >= len(chunk) {
				break
			}
		}
		if len(out) >= maxHits {
			break
		}
		next := off + readLen - overlap
		if next <= off {
			next = off + readLen
		}
		off = next
	}
	return out, nil
}

type diskPartition struct {
	startLBA int64
	sizeLBA  int64
	kind     string // "gpt" or "mbr"
	name     string // gpt name or empty
	typ      string // gpt type GUID or mbr type byte
	index    int
}

func (p diskPartition) label() string {
	if p.kind == "gpt" && p.name != "" {
		return p.kind + ":" + p.name
	}
	return p.kind
}

func readDiskPartitions(r io.ReaderAt, totalSize int64, blockSize int64) ([]diskPartition, error) {
	// Prefer GPT if present; otherwise fall back to MBR.
	gptParts, err := readGPT(r, blockSize)
	if err == nil && len(gptParts) > 0 {
		return gptParts, nil
	}
	return readMBR(r, totalSize, blockSize)
}

func readGPT(r io.ReaderAt, blockSize int64) ([]diskPartition, error) {
	// GPT header at LBA 1.
	sector := make([]byte, blockSize)
	if _, err := r.ReadAt(sector, blockSize); err != nil {
		return nil, err
	}
	if !bytes.Equal(sector[0:8], []byte("EFI PART")) {
		return nil, io.EOF
	}

	headerSize := binary.LittleEndian.Uint32(sector[12:16])
	if headerSize < 92 || headerSize > uint32(blockSize) {
		return nil, io.ErrUnexpectedEOF
	}

	partEntryLBA := int64(binary.LittleEndian.Uint64(sector[72:80]))
	numEntries := int(binary.LittleEndian.Uint32(sector[80:84]))
	entrySize := int(binary.LittleEndian.Uint32(sector[84:88]))
	if numEntries <= 0 || entrySize < 128 || entrySize > int(blockSize) {
		return nil, io.ErrUnexpectedEOF
	}

	entriesBytes := int64(numEntries * entrySize)
	buf := make([]byte, entriesBytes)
	if _, err := r.ReadAt(buf, partEntryLBA*blockSize); err != nil {
		return nil, err
	}

	out := make([]diskPartition, 0)
	for i := 0; i < numEntries; i++ {
		e := buf[i*entrySize : (i+1)*entrySize]
		// type GUID all zeros => unused
		allZero := true
		for _, b := range e[0:16] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}

		firstLBA := int64(binary.LittleEndian.Uint64(e[32:40]))
		lastLBA := int64(binary.LittleEndian.Uint64(e[40:48]))
		if firstLBA <= 0 || lastLBA < firstLBA {
			continue
		}

		// UTF-16LE name (72 bytes => 36 uint16)
		nameU16 := make([]uint16, 36)
		for j := 0; j < 36; j++ {
			nameU16[j] = binary.LittleEndian.Uint16(e[56+j*2 : 56+j*2+2])
		}
		name := string(utf16.Decode(trimU16Null(nameU16)))

		out = append(out, diskPartition{
			startLBA: firstLBA,
			sizeLBA:  lastLBA - firstLBA + 1,
			kind:     "gpt",
			name:     name,
			typ:      bytesToHexGuid(e[0:16]),
			index:    i + 1,
		})
	}

	return out, nil
}

func readMBR(r io.ReaderAt, totalSize int64, blockSize int64) ([]diskPartition, error) {
	// Read MBR at LBA 0.
	sector := make([]byte, blockSize)
	if _, err := r.ReadAt(sector, 0); err != nil {
		return nil, err
	}
	if sector[510] != 0x55 || sector[511] != 0xAA {
		return nil, io.EOF
	}

	out := make([]diskPartition, 0)

	// Primary partitions (including extended).
	for i := 0; i < 4; i++ {
		ent := sector[446+i*16 : 446+(i+1)*16]
		typ := ent[4]
		start := int64(binary.LittleEndian.Uint32(ent[8:12]))
		size := int64(binary.LittleEndian.Uint32(ent[12:16]))
		if typ == 0 || size == 0 {
			continue
		}
		if isExtendedMBRType(typ) {
			logicals, err := readMBRExtended(r, start, blockSize)
			if err != nil {
				return nil, err
			}
			out = append(out, logicals...)
			continue
		}
		out = append(out, diskPartition{
			startLBA: start,
			sizeLBA:  size,
			kind:     "mbr",
			typ:      "0x" + hexByte(typ),
			index:    i + 1,
		})
	}

	_ = totalSize // kept for parity; not needed for basic MBR parsing
	return out, nil
}

func readMBRExtended(r io.ReaderAt, extendedStartLBA int64, blockSize int64) ([]diskPartition, error) {
	out := make([]diskPartition, 0)
	ebrLBA := extendedStartLBA
	index := 0

	for {
		sector := make([]byte, blockSize)
		if _, err := r.ReadAt(sector, ebrLBA*blockSize); err != nil {
			return nil, err
		}
		if sector[510] != 0x55 || sector[511] != 0xAA {
			break
		}

		// Entry 0: logical partition relative to this EBR.
		ent0 := sector[446 : 446+16]
		typ0 := ent0[4]
		start0 := int64(binary.LittleEndian.Uint32(ent0[8:12]))
		size0 := int64(binary.LittleEndian.Uint32(ent0[12:16]))
		if typ0 != 0 && size0 > 0 {
			index++
			out = append(out, diskPartition{
				startLBA: ebrLBA + start0,
				sizeLBA:  size0,
				kind:     "mbr",
				typ:      "0x" + hexByte(typ0),
				index:    index,
			})
		}

		// Entry 1: pointer to next EBR relative to the extended start.
		ent1 := sector[462 : 462+16]
		typ1 := ent1[4]
		start1 := int64(binary.LittleEndian.Uint32(ent1[8:12]))
		size1 := int64(binary.LittleEndian.Uint32(ent1[12:16]))
		if typ1 == 0 || size1 == 0 {
			break
		}

		// Next EBR is relative to the extended partition start.
		ebrLBA = extendedStartLBA + start1
	}

	return out, nil
}

func isExtendedMBRType(t byte) bool {
	// 0x05 (Extended CHS), 0x0F (Extended LBA), 0x85 (Linux Extended)
	return t == 0x05 || t == 0x0F || t == 0x85
}

func trimU16Null(s []uint16) []uint16 {
	n := len(s)
	for n > 0 && s[n-1] == 0 {
		n--
	}
	return s[:n]
}

func hexByte(b byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[b>>4], hexd[b&0x0F]})
}

func bytesToHexGuid(b []byte) string {
	// Raw bytes; not GUID canonical formatting (good enough for debug).
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexByte(x)...)
	}
	return string(out)
}

func findFirstOccurrence(r io.ReaderAt, size int64, needle []byte, maxBytes int64) (int64, bool, error) {
	if len(needle) == 0 || size <= 0 || maxBytes <= 0 {
		return 0, false, nil
	}
	limit := size
	if maxBytes < limit {
		limit = maxBytes
	}
	const chunkSize = int64(8 << 20) // 8 MiB
	buf := make([]byte, chunkSize)
	overlap := int64(len(needle) - 1)
	if overlap < 0 {
		overlap = 0
	}

	for off := int64(0); off < limit; {
		readLen := chunkSize
		if rem := limit - off; rem < readLen {
			readLen = rem
		}
		chunk := buf[:readLen]
		if _, err := r.ReadAt(chunk, off); err != nil {
			return 0, false, err
		}
		if idx := bytes.Index(chunk, needle); idx >= 0 {
			return off + int64(idx), true, nil
		}
		next := off + readLen - overlap
		if next <= off {
			next = off + readLen
		}
		off = next
	}
	return 0, false, nil
}

func findFirstOccurrenceTail(r io.ReaderAt, size int64, needle []byte, maxBytes int64) (int64, bool, error) {
	if len(needle) == 0 || size <= 0 || maxBytes <= 0 {
		return 0, false, nil
	}
	start := int64(0)
	if size > maxBytes {
		start = size - maxBytes
	}

	const chunkSize = int64(8 << 20) // 8 MiB
	buf := make([]byte, chunkSize)
	overlap := int64(len(needle) - 1)
	if overlap < 0 {
		overlap = 0
	}

	for off := start; off < size; {
		readLen := chunkSize
		if rem := size - off; rem < readLen {
			readLen = rem
		}
		chunk := buf[:readLen]
		if _, err := r.ReadAt(chunk, off); err != nil {
			return 0, false, err
		}
		if idx := bytes.Index(chunk, needle); idx >= 0 {
			return off + int64(idx), true, nil
		}
		next := off + readLen - overlap
		if next <= off {
			next = off + readLen
		}
		off = next
	}
	return 0, false, nil
}
