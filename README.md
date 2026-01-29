# go-bde

BitLocker Drive Encryption (BDE) metadata parser and decrypted volume reader in Go.

## Status

- Metadata parsing: **implemented** (Windows 7+ metadata block format)
- Unlocking: **implemented** (recovery password; AES-CCM unboxing VMK/FVEK)
- Decrypted volume reading: **implemented** (`io.ReaderAt` over decrypted volume data; metadata regions are zero-filled)

## Usage

### Detect BitLocker

```go
ok, err := bde.HasBitLockerBootSectorMarker(r) // fast marker check ("-FVE-FS-" in boot sector)
ok2, err := bde.IsBitLockerVolume(r)           // deeper probe (GUID locators + signature fallbacks)
_ = ok
_ = ok2
_ = err
```

### Parse metadata (no key required)

```go
f, _ := os.Open("bitlocker_volume.bin")
vol, _ := bde.New(f) // requires io.ReaderAt
fmt.Println(vol.Version(), vol.SectorSize())
```

### Unlock and read decrypted bytes (random access)

```go
f, _ := os.Open("bitlocker_volume.bin") // io.ReaderAt
vol, _ := bde.New(f)

// Recovery password: "111111-222222-...-888888"
_ = vol.UnlockWithRecoveryPassword("111111-222222-333333-444444-555555-666666-777777-888888", "")

stream, _ := vol.Open() // io.ReaderAt (decrypted view)
buf := make([]byte, 512)
_, _ = stream.ReadAt(buf, 0)
```

## Tests

- `go test ./...`: unit tests + optional image-based integration tests (skipped unless env vars are set).
- `-tags ntfs`: enables an optional integration test that unlocks a BitLocker partition and parses NTFS via `github.com/asalih/go-ntfs`.

Example:

```bash
GOPROXY=direct GOSUMDB=off \
GO_BDE_TEST_DISK_IMAGE="/path/to/disk.dd" \
GO_BDE_TEST_RECOVERY_PASSWORD_FILE="/path/to/recovery.key" \
go test ./... -tags ntfs -run TestUnlockAndReadNTFS_Image -v
```

## References

- The on-disk structures and behavior are based on the libyal `libbde` format documentation and tooling: [libyal/libbde](https://github.com/libyal/libbde)
