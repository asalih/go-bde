package bde

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// bootSectorData holds parsed boot sector information.
// This is an internal helper used during BDE initialization.
type bootSectorData struct {
	bootSector         BootSector
	sectorSize         int
	clusterSize        int
	informationOffsets []int64
	eowOffsets         []int64
}

func parseBootSector(r io.ReaderAt) (*bootSectorData, error) {
	bsd := &bootSectorData{}

	// Read boot sector at offset 0.
	sr := sectionReader(r, 0)
	if err := binary.Read(sr, binary.LittleEndian, &bsd.bootSector); err != nil {
		return nil, err
	}

	// Calculate sector and cluster sizes.
	//
	// Prefer BPB values when present; fall back to shift fields (BitLocker/NTFS style).
	switch bsd.bootSector.Bpb.BytesPerSector {
	case 512, 1024, 2048, 4096:
		bsd.sectorSize = int(bsd.bootSector.Bpb.BytesPerSector)
	default:
		// Be conservative: if shift values look invalid, fall back to common defaults.
		if bsd.bootSector.BytesPerSectorShift < 9 || bsd.bootSector.BytesPerSectorShift > 12 {
			bsd.sectorSize = 512
		} else {
			bsd.sectorSize = 1 << bsd.bootSector.BytesPerSectorShift
		}
	}
	if bsd.bootSector.Bpb.SectorsPerCluster > 0 {
		bsd.clusterSize = bsd.sectorSize * int(bsd.bootSector.Bpb.SectorsPerCluster)
	} else if bsd.bootSector.SectorsPerClusterShift > 25 { // defensive upper bound
		bsd.clusterSize = bsd.sectorSize
	} else {
		bsd.clusterSize = bsd.sectorSize * (1 << bsd.bootSector.SectorsPerClusterShift)
	}

	// Read GUID locator blocks.
	var err error
	bsd.informationOffsets, bsd.eowOffsets, err = readGuidBlocks(r, bsd.sectorSize, bsd.clusterSize, bsd.bootSector)
	if err != nil {
		return nil, err
	}

	// If no GUID locators found, try extracting offsets from boot sector fixed positions.
	// Some BitLocker images store FVE metadata offsets at 0x30, 0x38, 0x40 without GUID locators.
	if len(bsd.informationOffsets) == 0 {
		bsd.informationOffsets = tryBootSectorOffsets(r, bsd.sectorSize, bsd.clusterSize)
	}

	return bsd, nil
}

// tryBootSectorOffsets attempts to extract FVE metadata offsets from fixed boot sector positions.
// This is a fallback when GUID locator blocks are not present.
func tryBootSectorOffsets(r io.ReaderAt, sectorSz, clusterSz int) []int64 {
	// Read the boot sector raw bytes at the positions where FVE offsets may be stored.
	// Common positions: 0x30, 0x38, 0x40 (3 metadata copies)
	var rawOffsets [24]byte
	if _, err := r.ReadAt(rawOffsets[:], 0x30); err != nil {
		return nil
	}

	clusterSize := int64(clusterSz)
	sectorSize := int64(sectorSz)
	if clusterSize <= 0 {
		clusterSize = 4096
	}
	if sectorSize <= 0 {
		sectorSize = 512
	}

	var offsets []int64
	seen := make(map[int64]bool)

	for i := 0; i < 3; i++ {
		rawVal := binary.LittleEndian.Uint64(rawOffsets[i*8 : (i+1)*8])
		if rawVal == 0 || rawVal > uint64(1)<<48 { // Skip obviously invalid values
			continue
		}

		// Try multiple interpretations of the value:
		// 1. As a byte offset directly
		// 2. As a sector offset (multiply by sector size)
		// 3. As a cluster offset (multiply by cluster size)
		candidates := []int64{
			int64(rawVal),                   // Direct byte offset
			int64(rawVal) * sectorSize,      // Sector-based
			int64(rawVal) * clusterSize,     // Cluster-based
		}

		for _, offset := range candidates {
			if offset <= 0 || offset > int64(1)<<44 { // Skip invalid offsets (>16 TiB)
				continue
			}
			if seen[offset] {
				continue
			}
			// Quick check: does this offset have the BitLocker signature?
			var sig [8]byte
			if _, err := r.ReadAt(sig[:], offset); err != nil {
				continue
			}
			if bytes.Equal(sig[:], BITLOCKER_SIGNATURE) {
				seen[offset] = true
				offsets = append(offsets, offset)
			}
		}
	}

	return offsets
}

const maxSectionSize = int64(^uint64(0) >> 1)

// readGuidBlocks scans the first sectors for BitLocker GUID locator blocks.
func readGuidBlocks(r io.ReaderAt, sectorSz, clusterSz int, bs BootSector) ([]int64, []int64, error) {
	tryScan := func(sectorSize int64, maxSectors int64) ([]int64, []int64, error) {
		var infoOffsets []int64
		var eowOffsets []int64

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
				for i := 0; i < eowCount; i++ {
					off := binary.LittleEndian.Uint64(raw[infoCount*8+i*8 : infoCount*8+(i+1)*8])
					if off != 0 {
						eowOffsets = append(eowOffsets, int64(off))
					}
				}
				return nil
			}

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
			for i := 0; i < eowCount; i++ {
				off := binary.LittleEndian.Uint64(raw[infoCount*8+i*8 : infoCount*8+(i+1)*8])
				if off != 0 {
					eowOffsets = append(eowOffsets, int64(off))
				}
			}
			return nil
		}

		for sector := int64(0); sector < maxSectors; sector++ {
			offset := sector * sectorSize
			if _, err := r.ReadAt(sec, offset); err != nil {
				return nil, nil, err
			}

			// Check for EOW-capable locator first (it includes both info and EOW offsets).
			if idx := bytes.Index(sec, EOW_INFORMATION_OFFSET_GUID[:]); idx >= 0 {
				if err := parseOffsets(offset, idx, 3, 2); err != nil {
					return nil, nil, err
				}
			} else if idx := bytes.Index(sec, INFORMATION_OFFSET_GUID[:]); idx >= 0 {
				// Standard locator (3 info offsets only).
				if err := parseOffsets(offset, idx, 3, 0); err != nil {
					return nil, nil, err
				}
			}
		}

		return infoOffsets, eowOffsets, nil
	}

	// First attempt: derived sector size, scan deeper.
	info, eow, err := tryScan(int64(sectorSz), 256)
	if err != nil {
		return nil, nil, err
	}
	if len(info) > 0 || len(eow) > 0 {
		return info, eow, nil
	}

	// Fallbacks for images where the shift fields are unreliable or 4K-native.
	if sectorSz != 512 {
		info, eow, err = tryScan(512, 256)
		if err != nil {
			return nil, nil, err
		}
		if len(info) > 0 || len(eow) > 0 {
			return info, eow, nil
		}
	}
	if sectorSz != 4096 {
		info, eow, err = tryScan(4096, 256)
		if err != nil {
			return nil, nil, err
		}
		if len(info) > 0 || len(eow) > 0 {
			return info, eow, nil
		}
	}

	// Final fallback: use InformationLcn if present (offset in clusters).
	if bs.InformationLcn != 0 && clusterSz > 0 {
		return []int64{int64(bs.InformationLcn) * int64(clusterSz)}, nil, nil
	}

	return nil, nil, nil
}

// BDE represents a BitLocker Drive Encryption (BDE) volume.
type BDE struct {
	r           io.ReaderAt
	sectorSize  int
	clusterSize int

	information    *Information
	eowInformation *EowInformation

	validInformation     []*Information
	availableInformation []*Information

	validEowInformation     []*EowInformation
	availableEowInformation []*EowInformation

	fvek     []byte
	fvekType FveKeyType
}

// New creates a new BDE reader over a random-access source.
//
// The size parameter specifies the total size of the volume in bytes.
// If size is 0, the function will attempt to get the size from r if it
// implements a Size() method; otherwise size-dependent features are disabled.
//
// This function uses GUID locator blocks to find Information block offsets,
// following the same approach as other BitLocker implementations (libbde, dissect.fve).
// It does NOT perform brute-force signature scanning.
func New(r io.ReaderAt, size int64) (*BDE, error) {
	bde := &BDE{r: r}

	// Parse boot sector to get sector/cluster sizes and initial offsets.
	bsd, err := parseBootSector(r)
	if err != nil {
		return nil, err
	}
	bde.sectorSize = bsd.sectorSize
	bde.clusterSize = bsd.clusterSize

	// Determine effective size: use provided size, or try to get from reader.
	effectiveSize := size
	if effectiveSize <= 0 {
		if sz, ok := readerSize(r); ok && sz > 0 {
			effectiveSize = sz
		}
	}

	// Read all Information blocks from GUID locator offsets.
	bde.availableInformation = []*Information{}
	infoOffsets := bsd.informationOffsets

	// If GUID locator scan didn't yield offsets and we have a valid size,
	// try scanning the tail of the partition for GUID locator blocks
	// (some layouts place locators near the end).
	if len(infoOffsets) == 0 && effectiveSize > 0 {
		tryTail := func(sectorSize int64, maxSectors int64) {
			if len(infoOffsets) > 0 || sectorSize <= 0 {
				return
			}
			windowBytes := sectorSize * maxSectors
			start := effectiveSize - windowBytes
			if start < 0 {
				start = 0
			}
			tail := io.NewSectionReader(r, start, effectiveSize-start)
			if offs, err := probeInformationOffsets(tail, sectorSize, maxSectors); err == nil && len(offs) > 0 {
				infoOffsets = offs
			}
		}

		tryTail(int64(bde.sectorSize), 8192)
		tryTail(512, 8192)
		tryTail(4096, 8192)
	}

	// Parse Information blocks from discovered offsets.
	for _, offset := range infoOffsets {
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

	// Prefer a valid (checksum verified) Information block, but be tolerant:
	// some images have mismatching CRCs while still being parseable.
	if len(bde.validInformation) > 0 {
		bde.information = bde.validInformation[0]
	} else if len(bde.availableInformation) > 0 {
		bde.information = bde.availableInformation[0]
	} else {
		return nil, InvalidHeaderError{Msg: "no BitLocker information block found (GUID locators missing or offsets invalid)"}
	}

	// Read EOW information blocks (if any).
	if len(bsd.eowOffsets) > 0 {
		bde.availableEowInformation = []*EowInformation{}
		for _, offset := range bsd.eowOffsets {
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
	return b.sectorSize
}

// Version returns the BitLocker metadata version.
func (b *BDE) Version() int {
	return b.information.Version()
}

// Paused reports whether encryption/decryption is paused.
func (b *BDE) Paused() bool {
	// Not currently derived from metadata entries.
	return false
}

// Decrypted reports whether the volume is already in decrypted state.
func (b *BDE) Decrypted() bool {
	// Treat as decrypted if encryption method is 0.
	return b.information != nil && b.information.dataset != nil && b.information.dataset.header.EncryptionMethod == 0
}

// Encrypted reports whether the volume is encrypted.
func (b *BDE) Encrypted() bool {
	return !b.Decrypted()
}

// Switching reports whether encryption/decryption is in progress.
func (b *BDE) Switching() bool {
	// Not currently derived from metadata entries.
	return false
}

// Unlocked reports whether the volume key has been obtained (or volume is decrypted).
func (b *BDE) Unlocked() bool {
	return b.fvek != nil || b.Decrypted()
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
		b.fvekType = keyType
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
	var lastErr error
	for _, vmk := range vmkDatums {
		decryptedKey, err := b.decryptVmkWithUserKey(vmk, userKey)
		if err != nil {
			lastErr = err
			continue
		}

		if err := b.Unlock(decryptedKey); err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
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

	bs := NewBitlockerStream(b)
	// If the volume is encrypted, we must have a cipher to read data.
	if !bs.passthrough && bs.cipher == nil {
		return nil, fmt.Errorf("unsupported or uninitialized cipher for encryption method: 0x%04x", uint16(b.fvekType))
	}
	return bs, nil
}

// ReservedRegions returns the reserved metadata regions as (startSector, numSectors).
func (b *BDE) ReservedRegions() [][2]int64 {
	var regions [][2]int64

	if b.Version() == 1 {
		informationSize := (b.clusterSize + 0x3FFF) & ^(b.clusterSize - 1)
		informationSectors := int64(informationSize / b.sectorSize)

		// Add Information offsets as reserved regions.
		for _, offset := range b.information.InformationOffsets() {
			sectors := offset / int64(b.sectorSize)
			regions = append(regions, [2]int64{sectors, informationSectors})
		}
	} else if b.Version() >= 2 {
		informationSize := ^(int64(b.sectorSize) - 1) & (int64(b.sectorSize) + 0xFFFF)
		informationSectors := informationSize / int64(b.sectorSize)

		// Add Information offsets as reserved regions.
		for _, offset := range b.information.InformationOffsets() {
			sectors := offset / int64(b.sectorSize)
			regions = append(regions, [2]int64{sectors, informationSectors})
		}

		// TODO: Virtualized block support (volume header sectors) can be derived from metadata block header.

		// EOW information.
		if b.eowInformation != nil {
			eowSize := ^(int64(b.sectorSize) - 1) & (int64(b.eowInformation.Size()) + int64(b.sectorSize) - 1)
			eowSectors := eowSize / int64(b.sectorSize)
			sectors := b.eowInformation.Offset() / int64(b.sectorSize)
			regions = append(regions, [2]int64{sectors, eowSectors})
		}
	}

	return regions
}

type reservedRegion struct {
	startSector int64 // inclusive
	endSector   int64 // exclusive
}

type sectorCipher interface {
	decryptSector(dst, src []byte, sectorNum uint64)
}

// BitlockerStream is a decrypted BitLocker volume stream.
type BitlockerStream struct {
	bde         *BDE
	offset      int64
	cipher      sectorCipher
	r           io.ReaderAt
	sectorSize  int64
	reserved    []reservedRegion
	passthrough bool // true when volume is already decrypted (no crypto needed)

	// BitLocker stores an encrypted copy of the first N sectors (volume header) at a different offset.
	// When set, reads for sectors [0, headerSectors) are served from headerOffset + sector*sectorSize.
	headerOffset  int64
	headerSectors int64
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
	if bde.information != nil {
		// These fields are in bytes/sectors relative to start of volume (libbde spec).
		bs.headerOffset = int64(bde.information.blockHeader.VolumeHeaderOff)
		bs.headerSectors = int64(bde.information.blockHeader.VolumeHeaderSectors)
	}
	if !bs.passthrough && bde.fvek != nil {
		switch bde.fvekType {
		case FveKeyTypeAesXts128, FveKeyTypeAesXts256:
			if c, err := newXTSCipher(bde.fvek); err == nil {
				bs.cipher = c
			}
		case FveKeyTypeAes128, FveKeyTypeAes256:
			if c, err := newCBCCipher(bde.fvek, int(bs.sectorSize)); err == nil {
				bs.cipher = c
			}
		}
	}
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
	cur := off
	dst := p

	for len(dst) > 0 {
		sector := cur / bs.sectorSize
		inSector := cur % bs.sectorSize
		remainInSector := bs.sectorSize - inSector
		toDo := int64(len(dst))
		if toDo > remainInSector {
			toDo = remainInSector
		}

		// Zero-fill reserved metadata sectors to preserve offsets.
		if bs.isReservedSector(sector) {
			for i := int64(0); i < toDo; i++ {
				dst[i] = 0
			}
			n += int(toDo)
			cur += toDo
			dst = dst[toDo:]
			continue
		}

		// Fast path: already decrypted, just ReadAt.
		if bs.passthrough {
			chunk := dst[:toDo]
			m, readErr := bs.r.ReadAt(chunk, cur)
			n += m
			cur += int64(m)
			dst = dst[m:]
			if readErr != nil {
				return n, cur, readErr
			}
			if int64(m) < toDo {
				return n, cur, io.EOF
			}
			continue
		}

		if bs.cipher == nil {
			return n, cur, errors.New("decryption is not initialized (volume not unlocked or cipher unsupported)")
		}

		// AES-XTS is sector-based: read and decrypt the full sector, then copy the requested range.
		sectorStart := cur - inSector
		// Virtual header sector mapping (BitLocker stores encrypted copy elsewhere).
		srcOffset := sectorStart
		if bs.headerOffset > 0 && bs.headerSectors > 0 && sector >= 0 && sector < bs.headerSectors {
			srcOffset = bs.headerOffset + sector*bs.sectorSize
		}
		// BitLocker sector crypto is sector-based. The "sector number" is derived from the
		// ciphertext location (srcOffset / sectorSize).
		sectorNum := uint64(srcOffset / bs.sectorSize)
		bp := sectorBufPool.Get().(*[]byte)
		sectorBuf := (*bp)[:bs.sectorSize]
		_, readErr := bs.r.ReadAt(sectorBuf, srcOffset)
		if readErr != nil {
			sectorBufPool.Put(bp)
			return n, cur, readErr
		}
		bs.cipher.decryptSector(sectorBuf, sectorBuf, sectorNum)

		copy(dst[:toDo], sectorBuf[inSector:inSector+toDo])
		sectorBufPool.Put(bp)

		n += int(toDo)
		cur += toDo
		dst = dst[toDo:]
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

// Seek moves the current offset.
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
