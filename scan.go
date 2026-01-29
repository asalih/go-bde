package bde

import (
	"bytes"
	"io"
)

type sizedReaderAt interface {
	io.ReaderAt
	Size() int64
}

func readerSize(r io.ReaderAt) (int64, bool) {
	if sr, ok := r.(interface{ Size() int64 }); ok {
		return sr.Size(), true
	}
	return 0, false
}

func findSignatureOffsets(r io.ReaderAt, size int64, sig []byte) ([]int64, error) {
	const (
		windowSize = int64(64 << 20) // 64 MiB
		chunkSize  = int64(4 << 20)  // 4 MiB
	)

	type window struct{ start, end int64 }
	windows := make([]window, 0, 2)
	if size > 0 {
		frontEnd := size
		if frontEnd > windowSize {
			frontEnd = windowSize
		}
		windows = append(windows, window{start: 0, end: frontEnd})

		if size > windowSize {
			windows = append(windows, window{start: size - windowSize, end: size})
		}
	}

	found := map[int64]struct{}{}
	out := make([]int64, 0)

	overlap := int64(len(sig) - 1)
	if overlap < 0 {
		overlap = 0
	}

	buf := make([]byte, chunkSize)
	for _, w := range windows {
		for off := w.start; off < w.end; {
			// Read chunk with overlap for boundary signatures.
			readLen := chunkSize
			if remaining := w.end - off; remaining < readLen {
				readLen = remaining
			}
			if readLen <= 0 {
				break
			}

			chunk := buf[:readLen]
			if _, err := r.ReadAt(chunk, off); err != nil {
				return nil, err
			}

			// Search all occurrences in this chunk.
			searchFrom := 0
			for {
				idx := bytes.Index(chunk[searchFrom:], sig)
				if idx < 0 {
					break
				}
				abs := off + int64(searchFrom+idx)
				if _, ok := found[abs]; !ok {
					found[abs] = struct{}{}
					out = append(out, abs)
				}
				searchFrom += idx + 1
				if searchFrom >= len(chunk) {
					break
				}
			}

			// Advance with overlap.
			next := off + readLen - overlap
			if next <= off {
				next = off + readLen
			}
			off = next
		}
	}

	return out, nil
}

func findInformationBlocksBySignature(r io.ReaderAt, size int64, maxFound int) ([]*Information, error) {
	if size <= 0 {
		return nil, nil
	}
	if maxFound <= 0 {
		maxFound = 1
	}

	// Scan forward; stop as soon as we have enough successfully parsed blocks.
	const chunkSize = int64(64 << 20) // 64 MiB
	buf := make([]byte, chunkSize)
	needle := BITLOCKER_SIGNATURE
	overlap := int64(len(needle) - 1)
	if overlap < 0 {
		overlap = 0
	}

	out := make([]*Information, 0, maxFound)
	seen := map[int64]struct{}{}

	for off := int64(0); off < size && len(out) < maxFound; {
		readLen := chunkSize
		if rem := size - off; rem < readLen {
			readLen = rem
		}
		chunk := buf[:readLen]
		if _, err := r.ReadAt(chunk, off); err != nil {
			return out, err
		}

		searchFrom := 0
		for len(out) < maxFound {
			idx := bytes.Index(chunk[searchFrom:], needle)
			if idx < 0 {
				break
			}
			abs := off + int64(searchFrom+idx)
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				if info, err := NewInformation(r, abs); err == nil {
					out = append(out, info)
				}
			}
			searchFrom += idx + 1
			if searchFrom >= len(chunk) {
				break
			}
		}

		next := off + readLen - overlap
		if next <= off {
			next = off + readLen
		}
		off = next
	}

	return out, nil
}

func findInformationBlocksBySignatureUntilEOF(r io.ReaderAt, maxBytes int64, maxFound int) ([]*Information, error) {
	if maxFound <= 0 {
		maxFound = 1
	}
	if maxBytes <= 0 {
		maxBytes = 2 << 30 // 2 GiB default cap
	}

	const chunkSize = int64(64 << 20) // 64 MiB
	buf := make([]byte, chunkSize)
	needle := BITLOCKER_SIGNATURE
	overlap := int64(len(needle) - 1)
	if overlap < 0 {
		overlap = 0
	}

	out := make([]*Information, 0, maxFound)
	seen := map[int64]struct{}{}

	for off := int64(0); off < maxBytes && len(out) < maxFound; {
		readLen := chunkSize
		if rem := maxBytes - off; rem < readLen {
			readLen = rem
		}
		chunk := buf[:readLen]
		n, err := r.ReadAt(chunk, off)
		if n > 0 {
			chunk = chunk[:n]
			searchFrom := 0
			for len(out) < maxFound {
				idx := bytes.Index(chunk[searchFrom:], needle)
				if idx < 0 {
					break
				}
				abs := off + int64(searchFrom+idx)
				if _, ok := seen[abs]; !ok {
					seen[abs] = struct{}{}
					if info, err2 := NewInformation(r, abs); err2 == nil {
						out = append(out, info)
					}
				}
				searchFrom += idx + 1
				if searchFrom >= len(chunk) {
					break
				}
			}
		}

		if err != nil {
			// Stop when the source says we're out of data.
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return out, err
		}

		next := off + int64(n) - overlap
		if next <= off {
			next = off + int64(n)
		}
		off = next
	}

	return out, nil
}

