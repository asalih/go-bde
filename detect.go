package bde

import (
	"bytes"
	"encoding/binary"
	"io"
)

const defaultProbeSectorSize = int64(512)

// IsBitLockerVolume reports whether the given random-access source looks like a BitLocker volume.
//
// It performs a fast probe by:
// - scanning the first sectors for a BitLocker GUID locator block
// - reading the referenced Information block(s) and checking the "-FVE-FS-" signature
func IsBitLockerVolume(r io.ReaderAt) (bool, error) {
	infoOffsets, err := probeInformationOffsets(r, defaultProbeSectorSize)
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

func probeInformationOffsets(r io.ReaderAt, sectorSize int64) ([]int64, error) {
	var infoOffsets []int64

	var guid [16]byte
	for sector := int64(0); sector < 20; sector++ {
		base := sector * sectorSize
		if _, err := r.ReadAt(guid[:], base); err != nil {
			return nil, err
		}

		switch {
		case bytes.Equal(guid[:], INFORMATION_OFFSET_GUID[:]):
			// 3 uint64 offsets follow.
			var raw [24]byte
			if _, err := r.ReadAt(raw[:], base+16); err != nil {
				return nil, err
			}
			for i := 0; i < 3; i++ {
				off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
				if off != 0 {
					infoOffsets = append(infoOffsets, int64(off))
				}
			}

		case bytes.Equal(guid[:], EOW_INFORMATION_OFFSET_GUID[:]):
			// 3 uint64 info offsets + 2 uint64 EOW offsets follow (ignore EOW offsets here).
			var raw [40]byte
			if _, err := r.ReadAt(raw[:], base+16); err != nil {
				return nil, err
			}
			for i := 0; i < 3; i++ {
				off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
				if off != 0 {
					infoOffsets = append(infoOffsets, int64(off))
				}
			}
		}
	}

	return infoOffsets, nil
}

