package bde

import "io"

// sectionReader creates an io.SectionReader starting at off without overflowing the length.
// It uses a best-effort maximum length bounded by maxSectionSize.
func sectionReader(r io.ReaderAt, off int64) *io.SectionReader {
	n := maxSectionSize
	if off >= 0 && off < maxSectionSize {
		n = maxSectionSize - off
	}
	return io.NewSectionReader(r, off, n)
}

