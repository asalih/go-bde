package bde

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"time"
	"unicode/utf16"
	"unsafe"
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
	header        FveInformation
	dataset       *Dataset
	buf           []byte
	validation    *Validation
	validChecksum bool
}

// NewInformation reads an Information block at the given offset.
func NewInformation(r io.ReaderAt, offset int64) (*Information, error) {
	info := &Information{offset: offset}

	// Read header.
	sr := io.NewSectionReader(r, offset, maxSectionSize)
	if err := binary.Read(sr, binary.LittleEndian, &info.header); err != nil {
		return nil, err
	}

	// Validate signature.
	if !bytes.Equal(info.header.Signature[:], BITLOCKER_SIGNATURE) {
		return nil, InvalidHeaderError{Msg: "invalid BitLocker information signature"}
	}

	// Read dataset starting after the header (sr has advanced).
	var err error
	info.dataset, err = NewDataset(sr)
	if err != nil {
		return nil, err
	}

	// Read full block into buffer for CRC/integrity checks.
	info.buf = make([]byte, info.Size())
	if _, err := r.ReadAt(info.buf, offset); err != nil {
		return nil, err
	}

	// Read validation which follows the Information block.
	validationReader := io.NewSectionReader(r, offset+int64(info.Size()), maxSectionSize)
	info.validation, err = NewValidation(validationReader)
	if err != nil {
		return nil, err
	}

	// Validate CRC32.
	info.validChecksum = crc32.ChecksumIEEE(info.buf) == info.validation.crc32

	return info, nil
}

// IsValid reports whether the Information block checksum is valid.
func (i *Information) IsValid() bool {
	return i.validChecksum
}

// CheckIntegrity validates the integrity check datum (when available).
func (i *Information) CheckIntegrity(key []byte) bool {
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

// Size returns the on-disk Information block size.
func (i *Information) Size() int {
	storedSize := int(i.header.HeaderSize)
	if i.Version() >= 2 {
		storedSize <<= 4
	}
	return storedSize
}

// Version returns the metadata version.
func (i *Information) Version() int {
	return int(i.header.Version)
}

// CurrentState returns the current volume state.
func (i *Information) CurrentState() FveState {
	return FveState(i.header.CurrentState)
}

// NextState returns the next volume state.
func (i *Information) NextState() FveState {
	return FveState(i.header.NextState)
}

// StateOffset returns the state offset.
func (i *Information) StateOffset() int64 {
	return int64(i.header.StateOffset)
}

// StateSize returns the state size.
func (i *Information) StateSize() int {
	return int(i.header.StateSize)
}

// VirtualizedSectors returns number of virtualized sectors.
func (i *Information) VirtualizedSectors() int {
	return int(i.header.VirtualizedSectors)
}

// VirtualizedBlockOffset returns the virtualization block offset.
func (i *Information) VirtualizedBlockOffset() int64 {
	return int64(i.header.VirtualizedBlockOffset)
}

// InformationOffsets returns the list of Information block offsets referenced by this header.
func (i *Information) InformationOffsets() []int64 {
	result := make([]int64, len(i.header.InformationOffset))
	for idx, offset := range i.header.InformationOffset {
		result[idx] = int64(offset)
	}
	return result
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
	header     FveDataset
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

	// Seek back and read the full dataset buffer.
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	ds.buf = make([]byte, ds.header.Size)
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

	// Read datums from StartOffset up to EndOffset.
	buf := bytes.NewReader(ds.buf[ds.header.StartOffset:ds.header.EndOffset])
	remaining := int(ds.header.EndOffset - ds.header.StartOffset)

	for remaining >= 8 { // minimum datum size (FveDatum)
		datum, err := ReadDatum(buf)
		if err != nil {
			return err
		}

		ds.data = append(ds.data, datum)
		remaining -= int(datum.size)
	}

	return nil
}

// FvekType returns the configured FVEK type.
func (ds *Dataset) FvekType() FveKeyType {
	return FveKeyType(ds.header.FvekType)
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

		priority := FveKeyProtector(vmkInfo.Priority)

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
		dataSize := int(datum.size) - 8 - int(unsafe.Sizeof(aes)) // 8=FveDatum
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
		structSize = int(unsafe.Sizeof(FveStretchKeyDatum{}))
	case FveDatumTypeUseKey:
		structSize = int(unsafe.Sizeof(FveUseKeyDatum{}))
	case FveDatumTypeVolumeMasterKeyInfo:
		structSize = int(unsafe.Sizeof(FveVmkInfo{}))
	case FveDatumTypeExternalInfo:
		structSize = int(unsafe.Sizeof(FveExternalInfo{}))
	}

	totalSize := int(d.size)
	dataSize := totalSize - headerSize - structSize

	if dataSize <= 0 {
		return nil
	}

	// Read properties.
	for dataSize > 0 {
		property, err := ReadDatum(r)
		if err != nil {
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

	// Extract AES-CCM encrypted payload.
	_, _, _, ciphertext, ok := d.GetAesCcmEncrypted()
	if !ok {
		return nil, errors.New("failed to read AES-CCM payload")
	}

	// TODO: Implement AES-CCM decryption (Go standard library does not provide CCM).

	// Avoid unused variable error until implemented.
	_ = ciphertext

	return nil, errors.New("AES-CCM decryption is not implemented")
}
