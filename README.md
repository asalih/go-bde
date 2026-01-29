# go-bde

BitLocker Drive Encryption (BDE) metadata parser and (eventually) volume reader in Go.

## Status

- Metadata parsing: **in progress**
- Unlocking (AES-CCM / VMK/FVEK unboxing): **not implemented**
- Decrypted volume reading: **supports `io.ReaderAt` / `io.Reader`** (skips reserved metadata sectors)

## Usage

```go
f, _ := os.Open("bitlocker_volume.bin")
vol, _ := bde.New(f) // requires io.ReaderAt
fmt.Println(vol.Version(), vol.SectorSize())
```
