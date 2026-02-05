package bde

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	defaultProbeSectorSize = int64(512)
	defaultProbeMaxSectors = int64(256) // more tolerant than 20; still cheap
)

// ProbeOptions controls BitLocker detection behavior.
type ProbeOptions struct {
	// SectorSize overrides the sector size used for scanning GUID locator blocks.
	// If zero, the function will try to derive sector size from the boot sector,
	// falling back to 512.
	SectorSize int64

	// MaxSectors is how many initial sectors to scan for GUID locator blocks.
	// If zero, a reasonable default is used.
	MaxSectors int64

	// AcceptSignatureAtOffset0 returns true immediately if "-FVE-FS-" is at offset 0.
	// This is useful when the provided reader is already rooted at an Information block
	// (not at the partition start).
	AcceptSignatureAtOffset0 bool
}

// IsBitLockerVolume reports whether the given random-access source looks like a BitLocker volume.
//
// It performs a fast probe by:
// - optionally accepting "-FVE-FS-" at offset 0
// - scanning the first sectors for a BitLocker GUID locator block
// - reading the referenced Information block(s) and checking the "-FVE-FS-" signature
func IsBitLockerVolume(r io.ReaderAt) (bool, error) {
	return IsBitLockerVolumeWithOptions(r, ProbeOptions{
		AcceptSignatureAtOffset0: true,
	})
}

// IsBitLockerVolumeWithOptions is like IsBitLockerVolume but allows tuning scan behavior.
func IsBitLockerVolumeWithOptions(r io.ReaderAt, opts ProbeOptions) (bool, error) {
	// Some callers hand us a reader that starts at an Information block rather than a partition.
	if opts.AcceptSignatureAtOffset0 {
		var sig0 [8]byte
		if _, err := r.ReadAt(sig0[:], 0); err == nil && bytes.Equal(sig0[:], BITLOCKER_SIGNATURE) {
			return true, nil
		}
	}

	sectorSize := opts.SectorSize
	if sectorSize <= 0 {
		sectorSize = deriveSectorSize(r)
	}

	maxSectors := opts.MaxSectors
	if maxSectors <= 0 {
		maxSectors = defaultProbeMaxSectors
	}

	infoOffsets, err := probeInformationOffsets(r, sectorSize, maxSectors)
	if err != nil {
		return false, err
	}
	if len(infoOffsets) == 0 {
		return false, nil
	}

	var sig [8]byte
	for _, off := range infoOffsets {
		if off < 0 {
			continue
		}
		if _, err := r.ReadAt(sig[:], off); err != nil {
			// If the image is too small to contain the advertised offset,
			// treat as unknown/invalid and return the error.
			return false, err
		}
		if bytes.Equal(sig[:], BITLOCKER_SIGNATURE) {
			return true, nil
		}
	}

	return false, nil
}

func deriveSectorSize(r io.ReaderAt) int64 {
	// Best-effort parse of boot sector shift fields.
	// If the caller didn't root us at partition start, this may not be a boot sector.
	var bs BootSector
	sr := sectionReader(r, 0)
	if err := binary.Read(sr, binary.LittleEndian, &bs); err == nil {
		shift := bs.BytesPerSectorShift
		// Typical sector size shifts: 9 (512), 10 (1024), 11 (2048), 12 (4096).
		if shift >= 9 && shift <= 12 {
			return int64(1) << shift
		}
	}
	return defaultProbeSectorSize
}

func probeInformationOffsets(r io.ReaderAt, sectorSize int64, maxSectors int64) ([]int64, error) {
	var infoOffsets []int64

	sec := make([]byte, sectorSize)
	parseOffsets := func(base int64, idx int, infoCount int, eowCount int) error {
		need := idx + 16 + (infoCount+eowCount)*8
		if need <= len(sec) {
			raw := sec[idx+16 : idx+16+(infoCount+eowCount)*8]
			for i := 0; i < infoCount; i++ {
				off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
				if off != 0 {
					infoOffsets = append(infoOffsets, int64(off))
				}
			}
			return nil
		}

		// Not enough bytes in the sector buffer; fall back to ReadAt.
		raw := make([]byte, (infoCount+eowCount)*8)
		if _, err := r.ReadAt(raw, base+int64(idx)+16); err != nil {
			return err
		}
		for i := 0; i < infoCount; i++ {
			off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
			if off != 0 {
				infoOffsets = append(infoOffsets, int64(off))
			}
		}
		return nil
	}

	for sector := int64(0); sector < maxSectors; sector++ {
		base := sector * sectorSize
		if _, err := r.ReadAt(sec, base); err != nil {
			return nil, err
		}

		// GUID locator blocks can appear at a non-zero offset within the sector.
		// Check for EOW-capable locator first (includes both info and EOW offsets).
		if idx := bytes.Index(sec, EOW_INFORMATION_OFFSET_GUID[:]); idx >= 0 {
			// EOW: 3 info offsets + 2 EOW offsets (ignored here).
			if err := parseOffsets(base, idx, 3, 2); err != nil {
				return nil, err
			}
		} else if idx := bytes.Index(sec, INFORMATION_OFFSET_GUID[:]); idx >= 0 {
			if err := parseOffsets(base, idx, 3, 0); err != nil {
				return nil, err
			}
		}
	}

	return infoOffsets, nil
}

// HasBitLockerBootSectorMarker reports whether the provided reader appears to start at a
// BitLocker-enabled partition boot sector.
//
// BitLocker volumes typically store the signature "-FVE-FS-" in the boot sector OEM field,
// which starts at offset 3 (immediately after the 3-byte jump instruction).
//
// This is a *marker* check; for a stronger validation that follows GUID locators and checks
// Information blocks, use IsBitLockerVolume / IsBitLockerVolumeWithOptions.
func HasBitLockerBootSectorMarker(r io.ReaderAt) (bool, error) {
	var oem [8]byte
	if _, err := r.ReadAt(oem[:], 3); err != nil {
		return false, err
	}
	return bytes.Equal(oem[:], BITLOCKER_SIGNATURE), nil
}

