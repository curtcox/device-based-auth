package dbaverify

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
)

// IETF OAuth Token Status List (1 bit per credential): bit i lives in byte floor(i/8) at
// position i % 8, least significant bit first; the byte array is zlib-compressed and base64url.

// MaxStatusListBytes caps decompression so a hostile list cannot exhaust memory (zip bomb).
const MaxStatusListBytes = 16 * 1024 * 1024

// Inflate decompresses zlib (RFC 1950) data, failing as soon as the output passes maxBytes.
func Inflate(data []byte, maxBytes int) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxBytes {
		return nil, errors.New("status list too large")
	}
	return out, nil
}

// Deflate compresses with zlib (RFC 1950).
func Deflate(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// MaxStatusIndex is the largest status-list index a credential may carry (spec/credential.md §7).
const MaxStatusIndex = 1<<31 - 1

// GetBit reads one status bit (1 = revoked). Indexes beyond the list are 0 (valid).
func GetBit(list []byte, index int64) int {
	if index < 0 || index/8 >= int64(len(list)) {
		return 0
	}
	return int(list[index/8]>>(uint(index%8))) & 1
}

// SetBit sets one status bit, growing the slice when needed, and returns the (possibly new) slice.
// It panics on an index outside 0..MaxStatusIndex, which an issuer never assigns.
func SetBit(list []byte, index int64, value int) []byte {
	if index < 0 || index > MaxStatusIndex {
		panic("status index out of range")
	}
	byteIndex := int(index / 8)
	out := list
	if byteIndex >= len(out) {
		size := max(byteIndex+1, len(out)*2)
		out = make([]byte, size)
		copy(out, list)
	}
	if value != 0 {
		out[byteIndex] |= 1 << (index % 8)
	} else {
		out[byteIndex] &^= 1 << (index % 8)
	}
	return out
}

// EncodeStatusList encodes bytes as a status_list claim ({bits: 1, lst}).
func EncodeStatusList(list []byte) *Object {
	return NewObject("bits", float64(1), "lst", B64U(Deflate(list)))
}

// DecodeStatusList decodes a status_list claim to bytes. Only 1-bit lists are supported.
func DecodeStatusList(claim any) ([]byte, error) {
	bits, _ := get(claim, "bits")
	lst, _ := get(claim, "lst")
	s, ok := lst.(string)
	if !strictEqual(bits, float64(1)) || !ok {
		return nil, errors.New("unsupported status list")
	}
	raw, err := UnB64U(s)
	if err != nil {
		return nil, err
	}
	return Inflate(raw, MaxStatusListBytes)
}
