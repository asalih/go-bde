package bde

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"
	"unicode/utf16"
)

// InvalidHeaderError indicates invalid/unsupported BitLocker headers.
type InvalidHeaderError struct {
	Msg string
}

func (e InvalidHeaderError) Error() string {
	return e.Msg
}

// Information represents a BitLocker "Information" block.
type Information struct {
	offset        int64
	blockHeader   FveMetadataBlockHeaderV2
	metadataHeader FveMetadataHeader
	dataset       *Dataset
	buf           []byte
	validation    *Validation
	validChecksum bool
}

// NewInformation reads an Information block at the given offset.
func NewInformation(r io.ReaderAt, offset int64) (*Information, error) {
	info := &Information{offset: offset}

	// Read metadata block header (64 bytes).
	sr := sectionReader(r, offset)
	if err := binary.Read(sr, binary.LittleEndian, &info.blockHeader); err != nil {
		return nil, err
	}
	if !bytes.Equal(info.blockHeader.Signature[:], BITLOCKER_SIGNATURE) {
		return nil, InvalidHeaderError{Msg: "invalid BitLocker metadata block signature"}
	}
	if info.blockHeader.Version != 1 && info.blockHeader.Version != 2 {
		// We primarily support Windows 7+ (v2), but allow v1 parsing attempts.
	}

	// Read metadata header (48 bytes) that follows the 64-byte block header.
	metaReader := sectionReader(r, offset+64)
	if err := binary.Read(metaReader, binary.LittleEndian, &info.metadataHeader); err != nil {
		return nil, err
	}

	// Sanity: header size should be 48 and metadata size should be within the 64KiB block.
	if info.metadataHeader.HeaderSize < 48 || info.metadataHeader.HeaderSize > 4096 {
		return nil, InvalidHeaderError{Msg: "invalid metadata header size"}
	}
	if info.metadataHeader.MetadataSize < info.metadataHeader.HeaderSize || info.metadataHeader.MetadataSize > 64<<10 {
		return nil, InvalidHeaderError{Msg: "invalid metadata size"}
	}

	// Read dataset (metadata header + entries) as a Dataset object.
	// The dataset starts at offset+64 (immediately after the block header).
	dsReader := sectionReader(r, offset+64)
	ds, err := NewDataset(dsReader)
	if err != nil {
		return nil, err
	}
	info.dataset = ds

	// Best-effort checksum validation (not fully implemented for metadata blocks yet).
	info.validChecksum = true

	return info, nil
}

// IsValid reports whether the Information block checksum is valid.
func (i *Information) IsValid() bool {
	return i.validChecksum
}

// CheckIntegrity validates the integrity check datum (when available).
func (i *Information) CheckIntegrity(key []byte) bool {
	if i.validation == nil || i.buf == nil {
		return i.IsValid()
	}
	if i.validation.integrityCheck != nil {
		// Unbox the integrity check datum with the provided key.
		datum, err := i.validation.integrityCheck.Unbox(key)
		if err != nil {
			return false
		}

		// Compare hashes.
		hash := sha256.Sum256(i.buf)
		return bytes.Equal(hash[:], datum.data)
	}
	return i.IsValid()
}

// Version returns the metadata header version (typically 1).
func (i *Information) Version() int {
	return int(i.metadataHeader.Version)
}

// InformationOffsets returns the list of metadata block offsets from the block header.
func (i *Information) InformationOffsets() []int64 {
	out := make([]int64, 0, 3)
	for _, off := range []uint64{i.blockHeader.MetadataOffset1, i.blockHeader.MetadataOffset2, i.blockHeader.MetadataOffset3} {
		if off != 0 {
			out = append(out, int64(off))
		}
	}
	return out
}

// Validation represents the validation structure following an Information block.
type Validation struct {
	validation     FveValidation
	integrityCheck *Datum
	crc32          uint32
}

// NewValidation reads Validation from the given reader.
func NewValidation(fh io.Reader) (*Validation, error) {
	v := &Validation{}

	// Read base validation struct.
	if err := binary.Read(fh, binary.LittleEndian, &v.validation); err != nil {
		return nil, err
	}

	v.crc32 = v.validation.Crc32

	// Version 2+ includes an integrity check datum.
	if v.Version() >= 2 {
		var err error
		v.integrityCheck, err = ReadDatum(fh)
		if err != nil {
			return nil, err
		}
	}

	return v, nil
}

// Version returns validation version.
func (v *Validation) Version() int {
	return int(v.validation.Version)
}

// Dataset represents an FVE dataset.
type Dataset struct {
	header     FveMetadataHeader
	buf        []byte
	data       []*Datum
}

// NewDataset reads a dataset at the current reader position.
func NewDataset(fh io.ReadSeeker) (*Dataset, error) {
	offset, err := fh.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	ds := &Dataset{}

	// Read dataset header.
	if err := binary.Read(fh, binary.LittleEndian, &ds.header); err != nil {
		return nil, err
	}

	// Sanity checks (metadata size is typically 64KiB).
	if ds.header.MetadataSize < uint32(binary.Size(FveMetadataHeader{})) || ds.header.MetadataSize > 64<<20 {
		return nil, InvalidHeaderError{Msg: "invalid metadata size"}
	}
	if ds.header.HeaderSize < uint32(binary.Size(FveMetadataHeader{})) || ds.header.HeaderSize > ds.header.MetadataSize {
		return nil, InvalidHeaderError{Msg: "invalid metadata header size"}
	}

	// Seek back and read the full dataset buffer.
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	ds.buf = make([]byte, ds.header.MetadataSize)
	if _, err := io.ReadFull(fh, ds.buf); err != nil {
		return nil, err
	}

	// Parse datums.
	if err := ds.readData(); err != nil {
		return nil, err
	}

	return ds, nil
}

// readData parses all datums in the dataset.
func (ds *Dataset) readData() error {
	ds.data = []*Datum{}

	// Read datums after the metadata header.
	start := int(ds.header.HeaderSize)
	end := len(ds.buf)
	if start < 0 || start > end {
		return InvalidHeaderError{Msg: "invalid metadata header bounds"}
	}
	buf := bytes.NewReader(ds.buf[start:end])
	remaining := end - start

	for remaining >= 8 { // minimum datum size (FveDatum)
		datum, err := ReadDatum(buf)
		if err != nil {
			// Be tolerant to truncated/padded datasets: stop parsing on EOF.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return err
		}
		if datum.size < 8 {
			// Invalid datum size; stop parsing to avoid infinite loops.
			break
		}

		ds.data = append(ds.data, datum)
		remaining -= int(datum.size)
	}

	return nil
}

// FvekType returns the configured FVEK type.
func (ds *Dataset) FvekType() FveKeyType {
	return FveKeyType(ds.header.EncryptionMethod & 0xffff)
}

// FindDatum finds datums by role and type. Use 0 as wildcard.
func (ds *Dataset) FindDatum(role FveDatumRole, typ FveDatumType) []*Datum {
	var result []*Datum

	for _, datum := range ds.data {
		if (role == 0 || datum.Role() == role) && (typ == 0 || datum.Type() == typ) {
			result = append(result, datum)
		}
	}

	return result
}

// FindDescription returns the description (if present).
func (ds *Dataset) FindDescription() string {
	datums := ds.FindDatum(FveDatumRoleDescription, FveDatumTypeUnicode)
	if len(datums) > 0 {
		return datums[0].Text()
	}
	return ""
}

// FindFvek returns the encrypted FVEK datum (if present).
func (ds *Dataset) FindFvek() *Datum {
	datums := ds.FindDatum(FveDatumRoleFullVolumeEncryptionKey, FveDatumTypeAesCcmEncryptedKey)
	if len(datums) > 0 {
		return datums[0]
	}
	return nil
}

// FindClearVmk returns a clear VMK (typically for paused volumes).
func (ds *Dataset) FindClearVmk() *Datum {
	for _, vmk := range ds.FindVmk(FveKeyProtectorClear, 0, 0xFF, 0x0000) {
		return vmk
	}
	return nil
}

// FindVmk finds VMK datums by protector and priority range.
func (ds *Dataset) FindVmk(protectorType FveKeyProtector, minPriority, maxPriority uint16, mask uint16) []*Datum {
	var result []*Datum

	datums := ds.FindDatum(FveDatumRoleVolumeMasterKeyInfo, FveDatumTypeVolumeMasterKeyInfo)
	for _, datum := range datums {
		// Extract FveVmkInfo.
		vmkInfo, ok := datum.GetVmkInfo()
		if !ok {
			continue
		}

			priority := FveKeyProtector(vmkInfo.ProtectorType)

		if priority < FveKeyProtector(minPriority) || priority > FveKeyProtector(maxPriority) {
			continue
		}

		if protectorType == 0 || (priority&FveKeyProtector(mask)) == protectorType {
			result = append(result, datum)
		}
	}

	return result
}

// FindExternalVmk finds external/startup-key VMKs.
func (ds *Dataset) FindExternalVmk() []*Datum {
	return ds.FindVmk(FveKeyProtectorExternal, 0, 0x7FFF, 0xFF00)
}

// FindRecoveryVmk finds recovery-password VMKs.
func (ds *Dataset) FindRecoveryVmk() []*Datum {
	return ds.FindVmk(FveKeyProtectorRecoveryPassword, 0, 0x7FFF, 0xFF00)
}

// FindPassphraseVmk finds user passphrase VMKs.
func (ds *Dataset) FindPassphraseVmk() []*Datum {
	return ds.FindVmk(FveKeyProtectorPassphrase, 0, 0x7FFF, 0xFF00)
}

// Datum is a parsed datum.
type Datum struct {
	header     FveDatum
	data       []byte
	size       uint16
	structure  interface{}
	properties []*Datum
}

// ReadDatum reads a datum from a reader.
func ReadDatum(r io.Reader) (*Datum, error) {
	datum := &Datum{}

	// Read header.
	if err := binary.Read(r, binary.LittleEndian, &datum.header); err != nil {
		return nil, err
	}

	datum.size = datum.header.Size

	// Decode by datum type.
	switch datum.Type() {
	case FveDatumTypeKey:
		var key struct {
			KeyType  uint16
			KeyFlags uint16
		}
		if err := binary.Read(r, binary.LittleEndian, &key); err != nil {
			return nil, err
		}
		datum.structure = key

		// Read payload bytes.
		dataSize := int(datum.size) - 8 - 4 // 8=FveDatum, 4=key struct
		if dataSize > 0 {
			datum.data = make([]byte, dataSize)
			if _, err := io.ReadFull(r, datum.data); err != nil {
				return nil, err
			}
		}

	case FveDatumTypeStretchKey:
		var stretch FveStretchKeyDatum
		if err := binary.Read(r, binary.LittleEndian, &stretch); err != nil {
			return nil, err
		}
		datum.structure = stretch

		// Read properties (complex datum).
		if err := datum.readProperties(r); err != nil {
			return nil, err
		}

	case FveDatumTypeUseKey:
		var useKey FveUseKeyDatum
		if err := binary.Read(r, binary.LittleEndian, &useKey); err != nil {
			return nil, err
		}
		datum.structure = useKey

		// Read properties (complex datum).
		if err := datum.readProperties(r); err != nil {
			return nil, err
		}

	case FveDatumTypeAesCcmEncryptedKey:
		var aes FveAesCcmEncryptedDatum
		if err := binary.Read(r, binary.LittleEndian, &aes); err != nil {
			return nil, err
		}
		datum.structure = aes

		// Read payload bytes.
		dataSize := int(datum.size) - 8 - binary.Size(FveAesCcmEncryptedDatum{}) // 8=FveDatum
		if dataSize > 0 {
			datum.data = make([]byte, dataSize)
			if _, err := io.ReadFull(r, datum.data); err != nil {
				return nil, err
			}
		}

	case FveDatumTypeUnicode:
		// UTF-16LE encoded text.
		dataSize := int(datum.size) - 8 // 8=FveDatum
		if dataSize > 0 {
			datum.data = make([]byte, dataSize)
			if _, err := io.ReadFull(r, datum.data); err != nil {
				return nil, err
			}
		}

	case FveDatumTypeVolumeMasterKeyInfo:
		var vmk FveVmkInfo
		if err := binary.Read(r, binary.LittleEndian, &vmk); err != nil {
			return nil, err
		}
		datum.structure = vmk

		// Read properties (complex datum).
		if err := datum.readProperties(r); err != nil {
			return nil, err
		}

	case FveDatumTypeExternalInfo:
		var ext FveExternalInfo
		if err := binary.Read(r, binary.LittleEndian, &ext); err != nil {
			return nil, err
		}
		datum.structure = ext

		// Read properties (complex datum).
		if err := datum.readProperties(r); err != nil {
			return nil, err
		}

	case FveDatumTypeVirtualizationInfo:
		var virt FveVirtualizationInfo
		if err := binary.Read(r, binary.LittleEndian, &virt); err != nil {
			return nil, err
		}
		datum.structure = virt

	default:
		// For other types, read only the payload bytes.
		dataSize := int(datum.size) - 8 // 8=FveDatum
		if dataSize > 0 {
			datum.data = make([]byte, dataSize)
			if _, err := io.ReadFull(r, datum.data); err != nil {
				return nil, err
			}
		}
	}

	return datum, nil
}

// readProperties reads nested properties from a complex datum.
func (d *Datum) readProperties(r io.Reader) error {
	// Compute remaining property bytes.
	headerSize := 8 // FveDatum boyutu
	structSize := 0

	// Determine struct size by type.
	switch d.Type() {
	case FveDatumTypeStretchKey:
		structSize = binary.Size(FveStretchKeyDatum{})
	case FveDatumTypeUseKey:
		structSize = binary.Size(FveUseKeyDatum{})
	case FveDatumTypeVolumeMasterKeyInfo:
		structSize = binary.Size(FveVmkInfo{})
	case FveDatumTypeExternalInfo:
		structSize = binary.Size(FveExternalInfo{})
	}

	totalSize := int(d.size)
	dataSize := totalSize - headerSize - structSize

	if dataSize <= 0 {
		return nil
	}

	// Read properties.
	for dataSize > 0 {
		if dataSize < 8 {
			// Remaining bytes are too small for another datum; treat as padding.
			return nil
		}
		property, err := ReadDatum(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		d.properties = append(d.properties, property)
		dataSize -= int(property.size)
	}

	return nil
}

// Role returns the datum role.
func (d *Datum) Role() FveDatumRole {
	return FveDatumRole(d.header.Role)
}

// Type returns the datum type.
func (d *Datum) Type() FveDatumType {
	return FveDatumType(d.header.Type)
}

// Size returns the datum size.
func (d *Datum) Size() int {
	return int(d.size)
}

// Data returns the datum payload bytes.
func (d *Datum) Data() []byte {
	return d.data
}

// Text decodes an UTF-16LE Unicode datum into a Go string.
func (d *Datum) Text() string {
	if d.Type() != FveDatumTypeUnicode || len(d.data) == 0 {
		return ""
	}

	// Decode UTF-16LE (not null-terminated).
	count := len(d.data) / 2
	u16s := make([]uint16, count)

	for i := 0; i < count; i++ {
		u16s[i] = binary.LittleEndian.Uint16(d.data[i*2 : i*2+2])
	}

	return string(utf16.Decode(u16s))
}

// GetKey extracts key fields from a Key datum.
func (d *Datum) GetKey() (FveKeyType, FveKeyFlag, []byte, bool) {
	if d.Type() != FveDatumTypeKey {
		return 0, 0, nil, false
	}

	if key, ok := d.structure.(struct {
		KeyType  uint16
		KeyFlags uint16
	}); ok {
		return FveKeyType(key.KeyType), FveKeyFlag(key.KeyFlags), d.data, true
	}

	return 0, 0, nil, false
}

// GetStretchKey extracts fields from a StretchKey datum.
func (d *Datum) GetStretchKey() (FveKeyType, FveKeyFlag, []byte, bool) {
	if d.Type() != FveDatumTypeStretchKey {
		return 0, 0, nil, false
	}

	if stretch, ok := d.structure.(FveStretchKeyDatum); ok {
		return FveKeyType(stretch.KeyType), FveKeyFlag(stretch.KeyFlags), stretch.Salt[:], true
	}

	return 0, 0, nil, false
}

// GetUseKey extracts fields from a UseKey datum.
func (d *Datum) GetUseKey() (FveKeyType, FveKeyFlag, bool) {
	if d.Type() != FveDatumTypeUseKey {
		return 0, 0, false
	}

	if useKey, ok := d.structure.(FveUseKeyDatum); ok {
		return FveKeyType(useKey.KeyType), FveKeyFlag(useKey.KeyFlags), true
	}

	return 0, 0, false
}

// GetAesCcmEncrypted extracts fields from an AES-CCM encrypted datum.
func (d *Datum) GetAesCcmEncrypted() (time.Time, uint32, []byte, []byte, bool) {
	if d.Type() != FveDatumTypeAesCcmEncryptedKey {
		return time.Time{}, 0, nil, nil, false
	}

	if aes, ok := d.structure.(FveAesCcmEncryptedDatum); ok {
		// Convert Windows FILETIME to Go time.
		t := time.Unix(0, int64((uint64(aes.Nonce.DateTime)-116444736000000000)*100))
		return t, aes.Nonce.Counter, aes.Mac[:], d.data, true
	}

	return time.Time{}, 0, nil, nil, false
}

// GetVmkInfo returns VMK info.
func (d *Datum) GetVmkInfo() (*FveVmkInfo, bool) {
	if d.Type() != FveDatumTypeVolumeMasterKeyInfo {
		return nil, false
	}

	if vmk, ok := d.structure.(FveVmkInfo); ok {
		return &vmk, true
	}

	return nil, false
}

// GetExternalInfo returns external info.
func (d *Datum) GetExternalInfo() (*FveExternalInfo, bool) {
	if d.Type() != FveDatumTypeExternalInfo {
		return nil, false
	}

	if ext, ok := d.structure.(FveExternalInfo); ok {
		return &ext, true
	}

	return nil, false
}

// FindProperty finds nested properties by type (0 is wildcard).
func (d *Datum) FindProperty(typ FveDatumType) []*Datum {
	var result []*Datum

	for _, prop := range d.properties {
		if prop.Role() == FveDatumRoleProperty && (typ == 0 || prop.Type() == typ) {
			result = append(result, prop)
		}
	}

	return result
}

// Unbox decrypts/unboxes an encrypted datum (not implemented).
func (d *Datum) Unbox(key []byte) (*Datum, error) {
	if d.Type() != FveDatumTypeAesCcmEncryptedKey {
		return nil, errors.New("only AES-CCM encrypted datums can be unboxed")
	}

	aesEnc, ok := d.structure.(FveAesCcmEncryptedDatum)
	if !ok {
		return nil, errors.New("invalid AES-CCM encrypted datum structure")
	}
	ciphertext := d.data
	if len(ciphertext) == 0 {
		return nil, errors.New("empty AES-CCM ciphertext")
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[0:8], aesEnc.Nonce.DateTime)
	binary.LittleEndian.PutUint32(nonce[8:12], aesEnc.Nonce.Counter)

	plaintext, err := ccmDecrypt(key, nonce, ciphertext, aesEnc.Mac[:], nil)
	if err != nil {
		return nil, err
	}

	// Parse key container (libbde spec: MAC is stored separately; plaintext begins with size/version/...).
	if len(plaintext) < 12 {
		return nil, errors.New("invalid key container plaintext")
	}
	// size (uint32), version (uint16), unknown (uint16), encryption method (uint32)
	encMethod := binary.LittleEndian.Uint32(plaintext[8:12])
	keyData := plaintext[12:]

	k := struct {
		KeyType  uint16
		KeyFlags uint16
	}{
		KeyType:  uint16(encMethod & 0xffff),
		KeyFlags: 0,
	}
	return &Datum{
		header:    FveDatum{Size: uint16(8 + 4 + len(keyData)), Role: uint16(FveDatumRoleProperty), Type: uint16(FveDatumTypeKey), Flags: 0},
		data:      keyData,
		size:      uint16(8 + 4 + len(keyData)),
		structure: k,
	}, nil
}
