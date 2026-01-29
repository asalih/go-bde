package bde

import (
	"bytes"
	"encoding/binary"
	"io"
)

// EowInformation represents BitLocker EOW information.
type EowInformation struct {
	offset        int64
	size          int
	header        []byte
	validChecksum bool
}

// NewEowInformation reads an EOW information structure at the given offset.
func NewEowInformation(r io.ReaderAt, offset int64) (*EowInformation, error) {
	eow := &EowInformation{
		offset: offset,
	}

	sr := io.NewSectionReader(r, offset, maxSectionSize)

	// Read signature.
	headerBuf := make([]byte, 8)
	if _, err := io.ReadFull(sr, headerBuf); err != nil {
		return nil, err
	}

	if !bytes.Equal(headerBuf, BITLOCKER_SIGNATURE) {
		return nil, InvalidHeaderError{Msg: "invalid EOW information signature"}
	}

	// Read header size.
	var headerSize uint16
	if err := binary.Read(sr, binary.LittleEndian, &headerSize); err != nil {
		return nil, err
	}

	// Read version.
	var version uint16
	if err := binary.Read(sr, binary.LittleEndian, &version); err != nil {
		return nil, err
	}

	// Compute total size.
	totalSize := int(headerSize)
	if version >= 2 {
		totalSize <<= 4
	}
	eow.size = totalSize

	eow.header = make([]byte, totalSize)
	if _, err := r.ReadAt(eow.header, offset); err != nil {
		return nil, err
	}

	// TODO: Implement checksum validation.
	eow.validChecksum = true // currently assumed valid

	return eow, nil
}

// IsValid reports whether EOW information is valid.
func (e *EowInformation) IsValid() bool {
	return e.validChecksum
}

// Offset returns the EOW information offset.
func (e *EowInformation) Offset() int64 {
	return e.offset
}

// Size returns the EOW information size.
func (e *EowInformation) Size() int {
	return e.size
}

// Header returns the raw EOW header bytes.
func (e *EowInformation) Header() []byte {
	return e.header
}
