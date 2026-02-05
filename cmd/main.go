package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/asalih/go-bde"
)

func main() {
	// Path to a BitLocker volume image in the testdata directory.
	volumePath := filepath.Join("testdata", "bitlocker_volume.bin")

	// Open the volume image.
	file, err := os.Open(volumePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	// Print file information.
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Failed to stat file: %v", err)
	}

	fmt.Printf("File name: %s\n", fileInfo.Name())
	fmt.Printf("File size: %d bytes\n", fileInfo.Size())
	fmt.Printf("Last modified: %v\n", fileInfo.ModTime())

	// Parse BitLocker metadata.
	vol, err := bde.New(file, 0)
	if err != nil {
		log.Fatalf("Failed to parse BitLocker metadata: %v", err)
	}
	decryptedVol, err := vol.Open()
	if err != nil {
		log.Fatalf("Failed to open BitLocker volume: %v", err)
	}

	decryptedVol.Read(make([]byte, 1024))
	fmt.Printf("BitLocker version: %d\n", vol.Version())
	fmt.Printf("Sector size: %d\n", vol.SectorSize())
	fmt.Printf("Description: %q\n", vol.Description())
	fmt.Printf("Encrypted: %v\n", vol.Encrypted())
	fmt.Printf("Paused: %v\n", vol.Paused())
	fmt.Printf("HasRecoveryPassword: %v\n", vol.HasRecoveryPassword())
	fmt.Printf("HasPassphrase: %v\n", vol.HasPassphrase())
	fmt.Printf("HasExternalKey: %v\n", vol.HasExternalKey())

	ids := vol.Identifiers()
	fmt.Printf("VMK identifiers found: %d\n", len(ids))
}
