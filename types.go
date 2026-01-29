package bde

// BDE signatures and GUIDs.
var (
	// BITLOCKER_SIGNATURE is the magic signature stored in BitLocker Information blocks.
	//
	// NOTE: This is a byte slice; treat it as read-only.
	BITLOCKER_SIGNATURE = []byte("-FVE-FS-")

	// GUID locator blocks (raw bytes as stored on disk).
	// Standard: 3bffd032-f3c4-4bf9-8745-c9012e926e5d
	INFORMATION_OFFSET_GUID = [16]byte{0x32, 0xd0, 0xff, 0x3b, 0xc4, 0xf3, 0xf9, 0x4b, 0x87, 0x45, 0xc9, 0x01, 0x2e, 0x92, 0x6e, 0x5d}
	// Standard (RFC 4122 byte order): 3bffd032-f3c4-4bf9-8745-c9012e926e5d
	// Some tools/images store the GUID in this order.
	INFORMATION_OFFSET_GUID_RFC4122 = [16]byte{0x3b, 0xff, 0xd0, 0x32, 0xf3, 0xc4, 0x4b, 0xf9, 0x87, 0x45, 0xc9, 0x01, 0x2e, 0x92, 0x6e, 0x5d}
	// EOW-capable: 3bffd032-f3c4-4bf9-8745-c90133d89632
	EOW_INFORMATION_OFFSET_GUID = [16]byte{0x32, 0xd0, 0xff, 0x3b, 0xc4, 0xf3, 0xf9, 0x4b, 0x87, 0x45, 0xc9, 0x01, 0x33, 0xd8, 0x96, 0x32}
	// EOW-capable (RFC 4122 byte order): 3bffd032-f3c4-4bf9-8745-c90133d89632
	EOW_INFORMATION_OFFSET_GUID_RFC4122 = [16]byte{0x3b, 0xff, 0xd0, 0x32, 0xf3, 0xc4, 0x4b, 0xf9, 0x87, 0x45, 0xc9, 0x01, 0x33, 0xd8, 0x96, 0x32}
)

// BDE states
type FveState uint16

const (
	FveStateDecrypted      FveState = iota + 1
	FveStateSwitchingDirty          // In-progress encryption or decryption of large volumes
	FveStatePaused                  // Seen on Vista volume with paused encryption/decryption
	FveStateEncrypted               // The most common state
	FveStateSwitching               // In-progress encryption or decryption of small volumes
)

// BDE key types
type FveKeyType uint16

const (
	FveKeyTypeNone     FveKeyType = 0x0000
	FveKeyTypeExternal FveKeyType = 0x0005 // External VMKs have a USE_KEY with this key type

	FveKeyTypeStretchKey  FveKeyType = 0x1000
	FveKeyTypeStretchKey1 FveKeyType = 0x1001
	FveKeyTypeAesCcm256_0 FveKeyType = 0x2000
	FveKeyTypeAesCcm256_1 FveKeyType = 0x2001
	FveKeyTypeExternKey   FveKeyType = 0x2002
	FveKeyTypeVmk         FveKeyType = 0x2003
	FveKeyTypeAesCcm256_2 FveKeyType = 0x2004
	FveKeyTypeHash256     FveKeyType = 0x2005

	FveKeyTypeAes128Diffuser FveKeyType = 0x8000
	FveKeyTypeAes256Diffuser FveKeyType = 0x8001
	FveKeyTypeAes128         FveKeyType = 0x8002
	FveKeyTypeAes256         FveKeyType = 0x8003
	FveKeyTypeAesXts128      FveKeyType = 0x8004
	FveKeyTypeAesXts256      FveKeyType = 0x8005
)

// BDE key protector types
type FveKeyProtector uint16

const (
	FveKeyProtectorClear            FveKeyProtector = 0x0000 // Also known as "obfuscated"
	FveKeyProtectorTpm              FveKeyProtector = 0x0100
	FveKeyProtectorExternal         FveKeyProtector = 0x0200 // Startup key
	FveKeyProtectorTpmPin           FveKeyProtector = 0x0400
	FveKeyProtectorRecoveryPassword FveKeyProtector = 0x0800 // Recovery password
	FveKeyProtectorPassphrase       FveKeyProtector = 0x2000 // User passphrase
)

// BDE key flags
type FveKeyFlag uint16

const (
	FveKeyFlagNone           FveKeyFlag = 0x00
	FveKeyFlagEnhancedPin    FveKeyFlag = 0x04
	FveKeyFlagEnhancedCrypto FveKeyFlag = 0x10
	FveKeyFlagPbkdf2         FveKeyFlag = 0x40
)

// BDE datum roles
type FveDatumRole uint16

const (
	FveDatumRoleProperty                 FveDatumRole = 0x0000
	FveDatumRoleUnknown1                 FveDatumRole = 0x0001
	FveDatumRoleVolumeMasterKeyInfo      FveDatumRole = 0x0002
	FveDatumRoleFullVolumeEncryptionKey  FveDatumRole = 0x0003
	FveDatumRoleValidation               FveDatumRole = 0x0004
	FveDatumRoleUnknown5                 FveDatumRole = 0x0005
	FveDatumRoleStartupKey               FveDatumRole = 0x0006
	FveDatumRoleDescription              FveDatumRole = 0x0007
	FveDatumRoleUnknown8                 FveDatumRole = 0x0008
	FveDatumRoleUnknown9                 FveDatumRole = 0x0009
	FveDatumRoleUnknownA                 FveDatumRole = 0x000A
	FveDatumRoleAutoUnlock               FveDatumRole = 0x000B
	FveDatumRoleFullVolumeEncryptionKey2 FveDatumRole = 0x000C
	FveDatumRoleUnknownD                 FveDatumRole = 0x000D
	FveDatumRoleUnknownE                 FveDatumRole = 0x000E
	FveDatumRoleVirtualizationInfo       FveDatumRole = 0x000F
	FveDatumRoleValidationHash           FveDatumRole = 0x0011
)

// BDE datum types
type FveDatumType uint16

const (
	FveDatumTypeErased                 FveDatumType = 0x0000
	FveDatumTypeKey                    FveDatumType = 0x0001
	FveDatumTypeUnicode                FveDatumType = 0x0002
	FveDatumTypeStretchKey             FveDatumType = 0x0003
	FveDatumTypeUseKey                 FveDatumType = 0x0004
	FveDatumTypeAesCcmEncryptedKey     FveDatumType = 0x0005
	FveDatumTypeTpmEncryptedBlob       FveDatumType = 0x0006
	FveDatumTypeValidationInfo         FveDatumType = 0x0007
	FveDatumTypeVolumeMasterKeyInfo    FveDatumType = 0x0008
	FveDatumTypeExternalInfo           FveDatumType = 0x0009
	FveDatumTypeUpdate                 FveDatumType = 0x000A
	FveDatumTypeErrorLog               FveDatumType = 0x000B
	FveDatumTypeAsymmetricEncryptedKey FveDatumType = 0x000C
	FveDatumTypeExportedKey            FveDatumType = 0x000D
	FveDatumTypePublicKeyInfo          FveDatumType = 0x000E
	FveDatumTypeVirtualizationInfo     FveDatumType = 0x000F
	FveDatumTypeSimple1                FveDatumType = 0x0010
	FveDatumTypeSimple2                FveDatumType = 0x0011
	FveDatumTypeConcatHashKey          FveDatumType = 0x0012
	FveDatumTypeSimple3                FveDatumType = 0x0013
	FveDatumTypeSimpleLarge            FveDatumType = 0x0014
	FveDatumTypeBackupInfo             FveDatumType = 0x0015
)

// BiosParameterBlock represents the BIOS Parameter Block structure
type BiosParameterBlock struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	ReservedSectors   uint16
	Fats              uint8
	RootEntries       uint16
	Sectors           uint16
	Media             uint8
	SectorsPerFat     uint16
	SectorsPerTrack   uint16
	Heads             uint16
	HiddenSectors     uint32
	LargeSectors      uint32
}

// BootSector represents the BitLocker Boot Sector structure
type BootSector struct {
	Jump                   [3]byte
	Oem                    [8]byte
	Bpb                    BiosParameterBlock
	Unused0                [20]byte
	InformationLcn         uint64 // Union with Mft2StartLcn
	Unused1                [8]byte
	PartitionLength        uint64
	Unused2                [28]byte
	BytesPerSectorShift    uint8
	SectorsPerClusterShift uint8
	Unused3                [402]byte
}

// FveMetadataBlockHeaderV2 represents the FVE metadata block header version 2 (Windows 7+).
// See libbde format spec.
type FveMetadataBlockHeaderV2 struct {
	Signature [8]byte
	Size      uint16
	Version   uint16 // 2
	Unknown1  uint16
	Unknown2  uint16

	EncryptedVolumeSize uint64
	Unknown3            uint32
	VolumeHeaderSectors uint32

	MetadataOffset1 uint64
	MetadataOffset2 uint64
	MetadataOffset3 uint64
	VolumeHeaderOff uint64
}

// FveMetadataHeader represents the FVE metadata header (version 1) inside a metadata block.
type FveMetadataHeader struct {
	MetadataSize     uint32
	Version          uint32
	HeaderSize       uint32
	MetadataSizeCopy uint32
	VolumeIdentifier [16]byte
	NextNonceCounter uint32
	EncryptionMethod uint32
	CreationTime     uint64
}

// FveDatum represents the base FVE Datum structure
type FveDatum struct {
	Size  uint16
	Role  uint16
	Type  uint16
	Flags uint16
}

// FveValidation represents the FVE Validation structure
type FveValidation struct {
	Size    uint16
	Version uint16
	Crc32   uint32
}

// FveStretchKeyDatum represents a stretch key datum structure
type FveStretchKeyDatum struct {
	KeyType  uint16
	KeyFlags uint16
	Salt     [16]byte
}

// FveUseKeyDatum represents a use key datum structure
type FveUseKeyDatum struct {
	KeyType  uint16
	KeyFlags uint16
}

// FveNonce represents an AES-CCM nonce structure
type FveNonce struct {
	DateTime uint64
	Counter  uint32
}

// FveAesCcmEncryptedDatum represents an AES-CCM encrypted datum structure
type FveAesCcmEncryptedDatum struct {
	Nonce FveNonce
	Mac   [16]byte
	// Data follows
}

// FveVmkInfo represents the VMK info entry value (type 0x0008).
type FveVmkInfo struct {
	GuidIdentifier [16]byte
	DateTime       uint64
	Unknown        uint16
	ProtectorType  uint16 // see FveKeyProtector
}

// FveExternalInfo represents the external info entry value (type 0x0009).
type FveExternalInfo struct {
	GuidIdentifier [16]byte
	DateTime       uint64
}

// FveVirtualizationInfo represents the virtualization info datum structure
type FveVirtualizationInfo struct {
	VirtualizedBlockOffset uint64
	VirtualizedBlockSize   uint64
}

// Cipher algorithm mapping
var CipherMap = map[FveKeyType]string{
	FveKeyTypeAes128Diffuser: "aes-128-diffuser",
	FveKeyTypeAes256Diffuser: "aes-256-diffuser",
	FveKeyTypeAes128:         "aes-128",
	FveKeyTypeAes256:         "aes-256",
	FveKeyTypeAesXts128:      "aes-xts-128",
	FveKeyTypeAesXts256:      "aes-xts-256",
}
