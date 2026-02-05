package bde

import "io"

func readerSize(r io.ReaderAt) (int64, bool) {
	if sr, ok := r.(interface{ Size() int64 }); ok {
		return sr.Size(), true
	}
	return 0, false
}
