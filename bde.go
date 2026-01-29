package bde

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

type BootSectorReader struct {
	r                  io.ReaderAt
	bootSector         BootSector
	sectorSize         int
	clusterSize        int
	informationOffsets []int64
	eowOffsets         []int64
}

func NewBootSectorReader(r io.ReaderAt) (*BootSectorReader, error) {
	bootReader := &BootSectorReader{r: r}

	// Read boot sector at offset 0.
	sr := io.NewSectionReader(r, 0, maxSectionSize)
	if err := binary.Read(sr, binary.LittleEndian, &bootReader.bootSector); err != nil {
		return nil, err
	}

	// Calculate sector and cluster sizes.
	bootReader.sectorSize = 1 << bootReader.bootSector.BytesPerSectorShift
	bootReader.clusterSize = bootReader.sectorSize * (1 << bootReader.bootSector.SectorsPerClusterShift)

	// Read GUID locator blocks.
	var err error
	bootReader.informationOffsets, bootReader.eowOffsets, err = bootReader.readGuidBlocks(r)
	if err != nil {
		return nil, err
	}

	return bootReader, nil
}

const maxSectionSize = int64(^uint64(0) >> 1)

// readGuidBlocks scans the first sectors for BitLocker GUID locator blocks.
func (b *BootSectorReader) readGuidBlocks(r io.ReaderAt) ([]int64, []int64, error) {
	// Store BitLocker metadata offsets found in GUID locator blocks.
	var infoOffsets []int64
	var eowOffsets []int64

	// Scan the first 20 sectors for known GUIDs.
	for sector := int64(0); sector < 20; sector++ {
		offset := sector * int64(b.sectorSize)
		var guidBuf [16]byte
		if _, err := r.ReadAt(guidBuf[:], offset); err != nil {
			return nil, nil, err
		}

		// GUID checks are done without a UUID package.
		if bytes.Equal(guidBuf[:], []byte{0x32, 0xd0, 0xff, 0x3b, 0xc4, 0xf3, 0xf9, 0x4b, 0x87, 0x45, 0xc9, 0x01, 0x2e, 0x92, 0x6e, 0x5d}) {
			// Standard FVE GUID block: 3 uint64 offsets follow.
			var raw [24]byte
			if _, err := r.ReadAt(raw[:], offset+16); err != nil {
				return nil, nil, err
			}
			for i := 0; i < 3; i++ {
				off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
				if off != 0 {
					infoOffsets = append(infoOffsets, int64(off))
				}
			}
		} else if bytes.Equal(guidBuf[:], []byte{0x32, 0xd0, 0xff, 0x3b, 0xc4, 0xf3, 0xf9, 0x4b, 0x87, 0x45, 0xc9, 0x01, 0x33, 0xd8, 0x96, 0x32}) {
			// EOW-capable FVE GUID block: 3 uint64 info offsets + 2 uint64 EOW offsets follow.
			var raw [40]byte
			if _, err := r.ReadAt(raw[:], offset+16); err != nil {
				return nil, nil, err
			}

			for i := 0; i < 3; i++ {
				off := binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
				if off != 0 {
					infoOffsets = append(infoOffsets, int64(off))
				}
			}
			for i := 0; i < 2; i++ {
				off := binary.LittleEndian.Uint64(raw[24+i*8 : 24+(i+1)*8])
				if off != 0 {
					eowOffsets = append(eowOffsets, int64(off))
				}
			}
		}
	}

	return infoOffsets, eowOffsets, nil
}

// SectorSize returns the sector size in bytes.
func (b *BootSectorReader) SectorSize() int {
	return b.sectorSize
}

// ClusterSize returns the cluster size in bytes.
func (b *BootSectorReader) ClusterSize() int {
	return b.clusterSize
}

// InformationOffsets returns discovered information offsets.
func (b *BootSectorReader) InformationOffsets() []int64 {
	return b.informationOffsets
}

// EowOffsets returns discovered EOW offsets.
func (b *BootSectorReader) EowOffsets() []int64 {
	return b.eowOffsets
}

// BDE represents a BitLocker Drive Encryption (BDE) volume.
type BDE struct {
	r              io.ReaderAt
	bootSector     *BootSectorReader
	information    *Information
	eowInformation *EowInformation

	validInformation     []*Information
	availableInformation []*Information

	validEowInformation     []*EowInformation
	availableEowInformation []*EowInformation

	fvek []byte
}

// New creates a new BDE reader over a random-access source.
func New(r io.ReaderAt) (*BDE, error) {
	bde := &BDE{r: r}

	var err error
	bde.bootSector, err = NewBootSectorReader(r)
	if err != nil {
		return nil, err
	}

	// Read all Information blocks.
	bde.availableInformation = []*Information{}
	for _, offset := range bde.bootSector.InformationOffsets() {
		info, err := NewInformation(r, offset)
		if err != nil {
			// Skip invalid information blocks.
			continue
		}
		bde.availableInformation = append(bde.availableInformation, info)
	}

	// Filter valid Information blocks.
	bde.validInformation = []*Information{}
	for _, info := range bde.availableInformation {
		if info.IsValid() {
			bde.validInformation = append(bde.validInformation, info)
		}
	}

	if len(bde.validInformation) == 0 {
		return nil, InvalidHeaderError{Msg: "no valid BitLocker information block found"}
	}

	// Use the first valid information block.
	bde.information = bde.validInformation[0]

	// Read EOW information blocks (if any).
	if len(bde.bootSector.EowOffsets()) > 0 {
		bde.availableEowInformation = []*EowInformation{}
		for _, offset := range bde.bootSector.EowOffsets() {
			eowInfo, err := NewEowInformation(r, offset)
			if err != nil {
				// Skip invalid EOW information blocks.
				continue
			}
			bde.availableEowInformation = append(bde.availableEowInformation, eowInfo)
		}

		// Filter valid EOW information blocks.
		bde.validEowInformation = []*EowInformation{}
		for _, eowInfo := range bde.availableEowInformation {
			if eowInfo.IsValid() {
				bde.validEowInformation = append(bde.validEowInformation, eowInfo)
			}
		}

		if len(bde.validEowInformation) > 0 {
			bde.eowInformation = bde.validEowInformation[0]
		}
	}

	return bde, nil
}

// Identifiers returns the VMK GUID identifiers present on the volume.
func (b *BDE) Identifiers() [][]byte {
	var result [][]byte

	datums := b.information.dataset.FindDatum(FveDatumRoleVolumeMasterKeyInfo, FveDatumTypeVolumeMasterKeyInfo)
	for _, datum := range datums {
		if vmkInfo, ok := datum.GetVmkInfo(); ok {
			id := make([]byte, 16)
			copy(id, vmkInfo.GuidIdentifier[:])
			result = append(result, id)
		}
	}

	return result
}

// SectorSize returns the sector size in bytes.
func (b *BDE) SectorSize() int {
	return b.bootSector.SectorSize()
}

// Version returns the BitLocker metadata version.
func (b *BDE) Version() int {
	return b.information.Version()
}

// Paused reports whether encryption/decryption is paused.
func (b *BDE) Paused() bool {
	return b.information.CurrentState() == FveStatePaused
}

// Decrypted reports whether the volume is already in decrypted state.
func (b *BDE) Decrypted() bool {
	return b.information.CurrentState() == FveStateDecrypted
}

// Encrypted reports whether the volume is encrypted.
func (b *BDE) Encrypted() bool {
	return !b.Decrypted()
}

// Switching reports whether encryption/decryption is in progress.
func (b *BDE) Switching() bool {
	state := b.information.CurrentState()
	return state != FveStateDecrypted && state != FveStateEncrypted
}

// Unlocked reports whether the volume key has been obtained (or volume is decrypted).
func (b *BDE) Unlocked() bool {
	return b.fvek != nil || b.information.CurrentState() == FveStateDecrypted
}

// Description returns the volume description (if present).
func (b *BDE) Description() string {
	return b.information.dataset.FindDescription()
}

// HasClearKey reports whether a clear VMK exists (typically for paused volumes).
func (b *BDE) HasClearKey() bool {
	return b.information.dataset.FindClearVmk() != nil
}

// HasRecoveryPassword reports whether a recovery-password protector exists.
func (b *BDE) HasRecoveryPassword() bool {
	return len(b.information.dataset.FindRecoveryVmk()) > 0
}

// HasPassphrase reports whether a user passphrase protector exists.
func (b *BDE) HasPassphrase() bool {
	return len(b.information.dataset.FindPassphraseVmk()) > 0
}

// HasExternalKey reports whether an external/startup-key protector exists.
func (b *BDE) HasExternalKey() bool {
	return len(b.information.dataset.FindExternalVmk()) > 0
}

// Unlock uses the given VMK to decrypt and store the FVEK.
func (b *BDE) Unlock(key []byte) error {
	// Validate integrity with the provided key.
	if !b.information.CheckIntegrity(key) {
		return errors.New("key validation failed")
	}

	// Find the encrypted FVEK datum.
	fvekDatum := b.information.dataset.FindFvek()
	if fvekDatum == nil {
		return errors.New("FVEK not found")
	}

	// Unbox the FVEK datum.
	unboxedDatum, err := fvekDatum.Unbox(key)
	if err != nil {
		return fmt.Errorf("failed to unbox FVEK: %w", err)
	}

	// Successful unlock: store FVEK key bytes.
	if keyType, _, keyData, ok := unboxedDatum.GetKey(); ok {
		b.fvek = keyData
		cipherType := CipherMap[keyType]
		if cipherType == "" {
			return fmt.Errorf("unsupported cipher type: %v", keyType)
		}
		return nil
	}

	return errors.New("unboxed FVEK datum is invalid")
}

// UnlockWithClearKey unlocks using a clear VMK (not implemented).
func (b *BDE) UnlockWithClearKey() error {
	vmk := b.information.dataset.FindClearVmk()
	if vmk == nil {
		return errors.New("clear VMK not found")
	}

	// TODO: Implement clear-key based unlock.

	return errors.New("unlock with clear key is not implemented")
}

// UnlockWithRecoveryPassword unlocks using a recovery password.
func (b *BDE) UnlockWithRecoveryPassword(recoveryPassword string, identifier string) error {
	// Derive the recovery key.
	recoveryKey, err := DeriveRecoveryKey(recoveryPassword)
	if err != nil {
		return err
	}

	return b.unlockWithUserKey(b.information.dataset.FindRecoveryVmk(), recoveryKey, identifier)
}

// UnlockWithPassphrase unlocks using a user passphrase.
func (b *BDE) UnlockWithPassphrase(passphrase string, identifier string) error {
	// Derive the user key.
	userKey := DeriveUserKey(passphrase)

	return b.unlockWithUserKey(b.information.dataset.FindPassphraseVmk(), userKey, identifier)
}

// UnlockWithExternalKey unlocks using a BEK (startup key) file (not implemented).
func (b *BDE) UnlockWithExternalKey(bekFh io.ReadSeeker) error {
	// Read dataset from the BEK file.
	bekDs, err := NewDataset(bekFh)
	if err != nil {
		return err
	}

	// Find the startup key datum in the BEK dataset.
	var startupKey *Datum
	for _, datum := range bekDs.FindDatum(FveDatumRoleStartupKey, FveDatumTypeExternalInfo) {
		startupKey = datum
		break
	}

	if startupKey == nil {
		return errors.New("startup key not found in BEK dataset")
	}

	// Extract the startup GUID.
	startupInfo, ok := startupKey.GetExternalInfo()
	if !ok {
		return errors.New("failed to read startup key info from BEK dataset")
	}

	// Find a matching VMK on the volume.
	var vmk *Datum

	for _, externalVmk := range b.information.dataset.FindExternalVmk() {
		vmkInfo, ok := externalVmk.GetVmkInfo()
		if !ok {
			continue
		}

		// Compare the GUIDs.
		if bytes.Equal(vmkInfo.GuidIdentifier[:], startupInfo.GuidIdentifier[:]) {
			vmk = externalVmk
			break
		}
	}

	if vmk == nil {
		return errors.New("no matching VMK found")
	}

	// TODO: Implement external key based unlock.

	return errors.New("unlock with external key is not implemented")
}

// unlockWithUserKey unlocks using a user key (passphrase or recovery password).
func (b *BDE) unlockWithUserKey(vmkDatums []*Datum, userKey []byte, identifier string) error {
	// If an identifier is provided, only try the matching VMK.
	if identifier != "" {
		for _, vmk := range vmkDatums {
			vmkInfo, ok := vmk.GetVmkInfo()
			if !ok {
				continue
			}

			// Build a GUID string without an extra dependency.
			guidBytes := make([]byte, 16)
			copy(guidBytes, vmkInfo.GuidIdentifier[:])
			guidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
				guidBytes[0:4],
				guidBytes[4:6],
				guidBytes[6:8],
				guidBytes[8:10],
				guidBytes[10:16])

			if guidStr != identifier {
				continue
			}

			decryptedKey, err := b.decryptVmkWithUserKey(vmk, userKey)
			if err != nil {
				return err
			}

			return b.Unlock(decryptedKey)
		}

		return errors.New("no matching VMK found for the provided identifier")
	}

	// Otherwise, try all candidate VMKs.
	for _, vmk := range vmkDatums {
		decryptedKey, err := b.decryptVmkWithUserKey(vmk, userKey)
		if err != nil {
			continue
		}

		if err := b.Unlock(decryptedKey); err != nil {
			continue
		}

		return nil
	}

	return errors.New("no compatible VMK found")
}

// decryptVmkWithUserKey decrypts a VMK using the derived user key.
func (b *BDE) decryptVmkWithUserKey(vmk *Datum, userKey []byte) ([]byte, error) {
	// Find Stretch Key datum.
	stretchKeyDatums := vmk.FindProperty(FveDatumTypeStretchKey)
	if len(stretchKeyDatums) == 0 {
		return nil, errors.New("stretch key not found")
	}

	// Extract salt.
	_, _, salt, ok := stretchKeyDatums[0].GetStretchKey()
	if !ok {
		return nil, errors.New("failed to read stretch key salt")
	}

	// Stretch the key.
	stretchedKey, err := Stretch(userKey, salt, 0)
	if err != nil {
		return nil, err
	}

	// Find AES-CCM encrypted key datum.
	encryptedKeys := vmk.FindProperty(FveDatumTypeAesCcmEncryptedKey)
	if len(encryptedKeys) == 0 {
		return nil, errors.New("encrypted key not found")
	}

	// Unbox the encrypted key.
	decryptedDatum, err := encryptedKeys[0].Unbox(stretchedKey)
	if err != nil {
		return nil, err
	}

	// Extract decrypted key bytes.
	if keyType, _, keyData, ok := decryptedDatum.GetKey(); ok {
		if keyType != FveKeyTypeVmk {
			return nil, fmt.Errorf("unexpected key type: %v", keyType)
		}
		return keyData, nil
	}

	return nil, errors.New("decrypted datum does not contain a valid key")
}

// Open returns a decrypted BitLocker volume stream.
func (b *BDE) Open() (*BitlockerStream, error) {
	if !b.Unlocked() {
		return nil, errors.New("volume is not unlocked")
	}

	return NewBitlockerStream(b), nil
}

// ReservedRegions returns the reserved metadata regions as (startSector, numSectors).
func (b *BDE) ReservedRegions() [][2]int64 {
	var regions [][2]int64

	if b.Version() == 1 {
		informationSize := (b.bootSector.ClusterSize() + 0x3FFF) & ^(b.bootSector.ClusterSize() - 1)
		informationSectors := int64(informationSize / b.bootSector.SectorSize())

		// Add Information offsets as reserved regions.
		for _, offset := range b.information.InformationOffsets() {
			sectors := offset / int64(b.bootSector.SectorSize())
			regions = append(regions, [2]int64{sectors, informationSectors})
		}
	} else if b.Version() >= 2 {
		informationSize := ^(int64(b.bootSector.SectorSize()) - 1) & (int64(b.bootSector.SectorSize()) + 0xFFFF)
		informationSectors := informationSize / int64(b.bootSector.SectorSize())

		// Add Information offsets as reserved regions.
		for _, offset := range b.information.InformationOffsets() {
			sectors := offset / int64(b.bootSector.SectorSize())
			regions = append(regions, [2]int64{sectors, informationSectors})
		}

		// Virtualized block.
		if b.information.VirtualizedSectors() > 0 {
			virtualizedSectors := int64(b.information.VirtualizedSectors())
			sectors := b.information.VirtualizedBlockOffset() / int64(b.bootSector.SectorSize())
			regions = append(regions, [2]int64{sectors, virtualizedSectors})
		}

		// EOW information.
		if b.eowInformation != nil {
			eowSize := ^(int64(b.bootSector.SectorSize()) - 1) & (int64(b.eowInformation.Size()) + int64(b.bootSector.SectorSize()) - 1)
			eowSectors := eowSize / int64(b.bootSector.SectorSize())
			sectors := b.eowInformation.Offset() / int64(b.bootSector.SectorSize())
			regions = append(regions, [2]int64{sectors, eowSectors})
		}
	}

	return regions
}

type reservedRegion struct {
	startSector int64 // inclusive
	endSector   int64 // exclusive
}

// BitlockerStream is a decrypted BitLocker volume stream.
type BitlockerStream struct {
	bde         *BDE
	offset      int64
	cipher      interface{} // TODO: replace with concrete cipher type when implemented
	r           io.ReaderAt
	sectorSize  int64
	reserved    []reservedRegion
	passthrough bool // true when volume is already decrypted (no crypto needed)
}

// NewBitlockerStream creates a new BitlockerStream.
func NewBitlockerStream(bde *BDE) *BitlockerStream {
	bs := &BitlockerStream{
		bde:         bde,
		r:           bde.r,
		sectorSize:  int64(bde.SectorSize()),
		passthrough: bde.Decrypted(),
	}
	bs.setReservedRegions(bde.ReservedRegions())
	return bs
}

func (bs *BitlockerStream) setReservedRegions(regions [][2]int64) {
	if len(regions) == 0 {
		bs.reserved = nil
		return
	}
	out := make([]reservedRegion, 0, len(regions))
	for _, r := range regions {
		if r[1] <= 0 {
			continue
		}
		out = append(out, reservedRegion{
			startSector: r[0],
			endSector:   r[0] + r[1],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].startSector < out[j].startSector })

	// Merge overlaps/adjacent regions.
	merged := out[:0]
	for _, rr := range out {
		if len(merged) == 0 {
			merged = append(merged, rr)
			continue
		}
		last := &merged[len(merged)-1]
		if rr.startSector <= last.endSector {
			if rr.endSector > last.endSector {
				last.endSector = rr.endSector
			}
			continue
		}
		merged = append(merged, rr)
	}
	bs.reserved = merged
}

func (bs *BitlockerStream) isReservedSector(sector int64) bool {
	if len(bs.reserved) == 0 {
		return false
	}
	// Find first region with startSector > sector, then check previous.
	i := sort.Search(len(bs.reserved), func(i int) bool { return bs.reserved[i].startSector > sector })
	if i == 0 {
		return false
	}
	rr := bs.reserved[i-1]
	return sector >= rr.startSector && sector < rr.endSector
}

func (bs *BitlockerStream) nextUnreservedOffset(off int64) int64 {
	sector := off / bs.sectorSize
	if !bs.isReservedSector(sector) {
		return off
	}
	// Jump to end of the region.
	i := sort.Search(len(bs.reserved), func(i int) bool { return bs.reserved[i].endSector > sector })
	if i < len(bs.reserved) && sector >= bs.reserved[i].startSector && sector < bs.reserved[i].endSector {
		return bs.reserved[i].endSector * bs.sectorSize
	}
	// Fallback: move one sector forward.
	return (sector + 1) * bs.sectorSize
}

func (bs *BitlockerStream) nextReservedStartOffset(off int64) int64 {
	sector := off / bs.sectorSize
	i := sort.Search(len(bs.reserved), func(i int) bool { return bs.reserved[i].startSector > sector })
	// Candidate is i (first region strictly after current sector), but we might already be in a region (handled elsewhere).
	if i < len(bs.reserved) {
		return bs.reserved[i].startSector * bs.sectorSize
	}
	return -1
}

func (bs *BitlockerStream) readAtInternal(p []byte, off int64) (n int, nextOff int64, err error) {
	if !bs.passthrough && bs.cipher == nil {
		return 0, off, errors.New("decryption is not initialized")
	}
	cur := off
	dst := p

	for len(dst) > 0 {
		cur = bs.nextUnreservedOffset(cur)

		// Limit the read to the next reserved region start to avoid reading reserved bytes.
		limit := int64(len(dst))
		if next := bs.nextReservedStartOffset(cur); next >= 0 && next > cur {
			maxToNext := next - cur
			if maxToNext < limit {
				limit = maxToNext
			}
		}
		if limit <= 0 {
			// We're exactly at a reserved boundary; advance and retry.
			cur += bs.sectorSize
			continue
		}

		chunk := dst[:limit]
		m, readErr := bs.r.ReadAt(chunk, cur)
		n += m
		cur += int64(m)
		dst = dst[m:]

		// TODO: Apply decryption to chunk[:m] when cipher is implemented.

		if readErr != nil {
			// io.ReaderAt is allowed to return (n>0, err==io.EOF). Respect that.
			return n, cur, readErr
		}

		// If we could not fill the requested chunk without an error, stop.
		if m < int(limit) {
			return n, cur, io.EOF
		}
	}

	return n, cur, nil
}

// Read reads from the current offset and advances it.
func (bs *BitlockerStream) Read(p []byte) (int, error) {
	n, next, err := bs.readAtInternal(p, bs.offset)
	if n > 0 {
		bs.offset = next
	}
	// If we read some bytes, return them even if err==io.EOF.
	if n > 0 && errors.Is(err, io.EOF) {
		return n, nil
	}
	return n, err
}

// ReadAt implements io.ReaderAt (random-access reads).
func (bs *BitlockerStream) ReadAt(p []byte, off int64) (int, error) {
	n, _, err := bs.readAtInternal(p, off)
	// If we read some bytes, return them even if err==io.EOF.
	if n > 0 && errors.Is(err, io.EOF) {
		return n, nil
	}
	return n, err
}

// Seek moves the current offset (best-effort; metadata regions are skipped forward).
func (bs *BitlockerStream) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64

	// Compute new offset based on whence.
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = bs.offset + offset
	case io.SeekEnd:
		return 0, errors.New("SeekEnd is not supported on ReaderAt-only sources")
	default:
		return 0, errors.New("invalid whence")
	}

	// Negative offsets are invalid.
	if newOffset < 0 {
		return 0, errors.New("negative offset")
	}

	// Skip forward if the target offset lands inside a reserved region.
	newOffset = bs.nextUnreservedOffset(newOffset)

	// Update offset.
	bs.offset = newOffset
	return newOffset, nil
}

// Close releases internal resources (no-op for the underlying source).
func (bs *BitlockerStream) Close() error {
	bs.cipher = nil
	return nil
}

// IsReservedSector reports whether the given sector is reserved for BitLocker metadata.
func (bs *BitlockerStream) IsReservedSector(sector int64) bool { return bs.isReservedSector(sector) }
