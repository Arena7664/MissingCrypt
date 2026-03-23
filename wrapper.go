package missingcrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

var (
	ErrEnvelopeTooShort = errors.New("missingcrypt: envelope too short")
	ErrBadHeaderMagic   = errors.New("missingcrypt: invalid outer header magic")
)

const (
	// envelopeHeaderSize is the fixed 24-byte outer header that precedes the
	// inner payload.
	envelopeHeaderSize = 24
	// envelopeFooterSize is the fixed 32-byte authentication footer that
	// follows the inner payload.
	envelopeFooterSize = 32
)

// Envelope holds the parsed fields of a decoded outer envelope. All slice
// fields are independent copies of the corresponding bytes from the original
// blob so the caller may safely discard the input after parsing.
type Envelope struct {
	// SeedByte is the low byte of the seed word (blob[0]). It is also used
	// directly as the rotation amount in ComputeFooter.
	SeedByte byte `json:"seed_byte"`
	// HeaderWord is the decoded seed word assembled from bytes 0,6,12,18.
	HeaderWord      uint32      `json:"header_word"`
	BigEndianHeader bool        `json:"big_endian_header"`
	AlgorithmID     AlgorithmID `json:"algorithm_id"`
	AlgorithmName   string      `json:"algorithm_name"`
	// HeaderParam seeds the per-message PRNG that derives the IV and length mask.
	HeaderParam uint32 `json:"header_param"`
	// RandomWord is used to obfuscate the algorithm ID and header param in the
	// encoded header. It is recovered from the bitwise-NOT of bytes 8,14,2,20.
	RandomWord      uint32 `json:"random_word"`
	InnerPrefix     []byte `json:"inner_prefix"`
	InnerCiphertext []byte `json:"inner_ciphertext"`
	Footer          []byte `json:"footer"`
	Raw             []byte `json:"raw"`
}

// ParseEnvelope decodes the 24-byte interleaved header from blob and returns
// the envelope fields. The header byte layout is:
//
//	byte  0, 6,12,18 → seed word            (assembly: little-endian uint32)
//	byte  1, 7,13,19 → version masked       = rol32(version XOR seed, seed)
//	byte  2, 8,14,20 → random word, NOT'd   (byte order: 16,0,8,24 of randomWord)
//	byte  3, 9,15,21 → algorithm ID masked  = algorithmID XOR randomWord
//	byte  4,10,16,22 → header param masked  = headerParam XOR bswap32(randomWord)
//	byte  5,11,17,23 → magic masked         = ror32(magic XOR seed, seed)
//
// When bigEndianHeader is set the algorithm ID, header param, magic, and
// version words are byte-swapped before the masking operations above, so the
// recovered values must be byte-swapped again on decode.
func ParseEnvelope(blob []byte) (*Envelope, error) {
	if len(blob) < envelopeHeaderSize+envelopeFooterSize {
		return nil, ErrEnvelopeTooShort
	}

	seed := blob[0]

	// Reconstruct the two 32-bit words that encode the magic value.
	// headerWord0 is assembled from the "seed" byte column (0,6,12,18).
	// headerWord1 is assembled from the "magic" byte column (5,11,17,23).
	headerWord0 := uint32(blob[0]) | uint32(blob[6])<<8 | uint32(blob[12])<<16 | uint32(blob[18])<<24
	headerWord1 := uint32(blob[5]) | uint32(blob[11])<<8 | uint32(blob[17])<<16 | uint32(blob[23])<<24

	// Recover the magic word: magicMasked = ror32(magic XOR seed, seed), so
	// magic XOR seed = rol32(magicMasked, seed), magic = rol32(...) XOR seed.
	// We check whether the result equals 0xABBAABBA in either byte order.
	magicCandidate := ror32(headerWord1, int((-seed)&31)) ^ headerWord0
	bigEndianHeader := binary.BigEndian.Uint32(u32le(magicCandidate)) == 0xABBAABBA
	if !bigEndianHeader && magicCandidate != 0xABBAABBA {
		return nil, fmt.Errorf("%w: got %#08x", ErrBadHeaderMagic, magicCandidate)
	}

	// Random word: stored bitwise-NOTed across bytes 8,14,2,20 in that order
	// (byte positions of randomWord bits 0-7, 8-15, 16-23, 24-31).
	randomWord := uint32(^blob[8]) |
		uint32(^blob[14])<<8 |
		uint32(^blob[2])<<16 |
		uint32(^blob[20])<<24

	// Algorithm ID: stored as (algorithmID XOR randomWord) at bytes 3,9,15,21.
	encodedAlg := uint32(blob[3]) |
		uint32(blob[9])<<8 |
		uint32(blob[15])<<16 |
		uint32(blob[21])<<24

	// Header param: stored as (headerParam XOR bswap32(randomWord)) at bytes
	// 4,10,16,22, but each byte is XORed with a different byte of randomWord
	// (bytes 24-31, 16-23, 8-15, 0-7 of randomWord respectively).
	encodedParam := uint32(blob[4]^byte(randomWord>>24)) |
		uint32(blob[10]^byte(randomWord>>16))<<8 |
		uint32(blob[16]^byte(randomWord>>8))<<16 |
		uint32(blob[22]^byte(randomWord))<<24

	algorithmID := encodedAlg ^ randomWord
	headerParam := encodedParam
	if bigEndianHeader {
		algorithmID = bswap32(algorithmID)
		headerParam = bswap32(headerParam)
	}
	algorithmName := algorithmSpecs[AlgorithmID(algorithmID)].Name

	return &Envelope{
		SeedByte:        seed,
		HeaderWord:      headerWord0,
		BigEndianHeader: bigEndianHeader,
		AlgorithmID:     AlgorithmID(algorithmID),
		AlgorithmName:   algorithmName,
		HeaderParam:     headerParam,
		RandomWord:      randomWord,
		InnerPrefix:     append([]byte(nil), blob[envelopeHeaderSize:envelopeHeaderSize+4]...),
		InnerCiphertext: append([]byte(nil), blob[envelopeHeaderSize+4:len(blob)-envelopeFooterSize]...),
		Footer:          append([]byte(nil), blob[len(blob)-envelopeFooterSize:]...),
		Raw:             append([]byte(nil), blob...),
	}, nil
}

// BuildEnvelope assembles a complete envelope: header + innerPayload + footer.
// innerPayload is the output of EncryptInner (4-byte clear prefix + ciphertext).
func BuildEnvelope(algorithmID AlgorithmID, headerParam uint32, seedWord uint32, randomWord uint32, innerPayload []byte, authKey []byte, bigEndianHeader bool) ([]byte, error) {
	header := encodeHeader(algorithmID, headerParam, seedWord, randomWord, bigEndianHeader)
	body := make([]byte, 0, len(header)+len(innerPayload))
	body = append(body, header[:]...)
	body = append(body, innerPayload...)

	footer, err := ComputeFooter(authKey, body, header[0])
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(body)+len(footer))
	out = append(out, body...)
	out = append(out, footer...)
	return out, nil
}

// encodeHeader serialises the five logical fields into the 24-byte interleaved
// header. Each 32-bit field is scattered across four non-consecutive bytes
// (columns 0..5 of a 6×4 matrix laid out row-major), which gives the header
// its characteristic non-sequential byte appearance.
func encodeHeader(algorithmID AlgorithmID, headerParam uint32, seedWord uint32, randomWord uint32, bigEndianHeader bool) [envelopeHeaderSize]byte {
	var out [envelopeHeaderSize]byte

	magicWord := uint32(0xABBAABBA)
	versionWord := uint32(0x112)
	algorithmWord := uint32(algorithmID)
	headerParamWord := headerParam
	// Big-endian mode byte-swaps the logical words before masking so that a
	// little-endian decoder reading them as uint32 recovers the byte-swapped
	// value, which it must then swap back. Server traffic always uses this mode.
	if bigEndianHeader {
		magicWord = bswap32(magicWord)
		versionWord = bswap32(versionWord)
		algorithmWord = bswap32(algorithmWord)
		headerParamWord = bswap32(headerParamWord)
	}

	magicMasked := ror32(magicWord^seedWord, int(seedWord))
	versionMasked := rol32(versionWord^seedWord, int(seedWord))
	algorithmMasked := algorithmWord ^ randomWord
	headerParamMasked := headerParamWord ^ bswap32(randomWord)

	// Column 0 (bytes 0,6,12,18): seed word.
	out[0] = byte(seedWord)
	out[6] = byte(seedWord >> 8)
	out[12] = byte(seedWord >> 16)
	out[18] = byte(seedWord >> 24)

	// Column 1 (bytes 1,7,13,19): version masked.
	out[1] = byte(versionMasked)
	out[7] = byte(versionMasked >> 8)
	out[13] = byte(versionMasked >> 16)
	out[19] = byte(versionMasked >> 24)

	// Column 2 (bytes 2,8,14,20): random word, bitwise-NOTed, byte order 16,0,8,24.
	out[2] = ^byte(randomWord >> 16)
	out[8] = ^byte(randomWord)
	out[14] = ^byte(randomWord >> 8)
	out[20] = ^byte(randomWord >> 24)

	// Column 3 (bytes 3,9,15,21): algorithm ID XOR random word.
	out[3] = byte(algorithmMasked)
	out[9] = byte(algorithmMasked >> 8)
	out[15] = byte(algorithmMasked >> 16)
	out[21] = byte(algorithmMasked >> 24)

	// Column 4 (bytes 4,10,16,22): header param XOR bswap32(random word).
	out[4] = byte(headerParamMasked)
	out[10] = byte(headerParamMasked >> 8)
	out[16] = byte(headerParamMasked >> 16)
	out[22] = byte(headerParamMasked >> 24)

	// Column 5 (bytes 5,11,17,23): magic XOR seed, rotated right by seed.
	out[5] = byte(magicMasked)
	out[11] = byte(magicMasked >> 8)
	out[17] = byte(magicMasked >> 16)
	out[23] = byte(magicMasked >> 24)

	return out
}

// ror32 rotates v right by n bit positions.
func ror32(v uint32, n int) uint32 { return bits.RotateLeft32(v, -n) }

// rol32 rotates v left by n bit positions.
func rol32(v uint32, n int) uint32 { return bits.RotateLeft32(v, n) }

// bswap32 reverses the byte order of a 32-bit word.
func bswap32(v uint32) uint32 {
	return binary.BigEndian.Uint32(u32le(v))
}

// u32le serialises v as a 4-byte little-endian slice.
func u32le(v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return buf[:]
}
