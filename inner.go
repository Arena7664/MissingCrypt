package missingcrypt

import (
	"encoding/binary"
	"errors"
)

// InnerPayload holds the decrypted inner content together with the metadata
// needed to reproduce or verify the encryption.
type InnerPayload struct {
	Plaintext []byte `json:"plaintext"`
	IV        []byte `json:"iv"`
	// LengthXor is the raw PRNG word XORed with the big-endian clear prefix to
	// recover the true plaintext length.
	LengthXor uint32 `json:"length_xor"`
	// PRNGKind is "mt19937" or "xor128", indicating which generator was used
	// to derive the IV and length mask for this message.
	PRNGKind string `json:"prng_kind"`
}

// DecryptInner decrypts the inner CBC payload and returns the plaintext together
// with the metadata needed to reproduce the encryption. clearPrefix is the
// 4-byte big-endian word immediately following the envelope header; it holds
// the plaintext length XORed with a PRNG-derived mask.
func DecryptInner(algorithmID AlgorithmID, headerParam uint32, derivedKey []byte, clearPrefix []byte, ciphertext []byte) (*InnerPayload, error) {
	return decryptInnerBlockCBC(algorithmID, headerParam, derivedKey, clearPrefix, ciphertext)
}

// EncryptInner encrypts plaintext and returns the 4-byte clear prefix
// (XORed length) followed by the CBC ciphertext.
func EncryptInner(algorithmID AlgorithmID, headerParam uint32, derivedKey []byte, plaintext []byte) ([]byte, error) {
	return encryptInnerBlockCBC(algorithmID, headerParam, derivedKey, plaintext)
}

// decryptInnerBlockCBC recovers plaintext from the inner CBC payload.
//
// The PRNG sequence used to derive per-message values is:
//
//	rng.Seed(headerParam)
//	discard = (rng.Next() & discardMask) + 1   // 1..mask+1 extra calls
//	for range discard { rng.Next() }            // discard N values
//	for each IV word  { putIVWord(rng.Next()) } // build IV
//	lengthXor = rng.Next()                      // mask for plaintext length
//
// The plaintext length is recovered by XORing the big-endian clear prefix
// with lengthXor. The ciphertext is padded to the block boundary with 0xFF
// bytes; padding is stripped by taking only the first `length` bytes.
func decryptInnerBlockCBC(algorithmID AlgorithmID, headerParam uint32, derivedKey []byte, clearPrefix []byte, ciphertext []byte) (*InnerPayload, error) {
	if len(clearPrefix) != 4 {
		return nil, errors.New("missingcrypt: clear prefix must be 4 bytes")
	}
	spec := MustAlgorithm(algorithmID)
	rng := newMessagePRNG(headerParam, spec.ID)
	rng.Seed(headerParam)
	discard := (rng.Next() & discardMask(spec.ID)) + 1
	for range discard {
		rng.Next()
	}

	iv := make([]byte, spec.BlockSize)
	for offset := 0; offset < len(iv); offset += 4 {
		putIVWord(iv[offset:offset+4], algorithmID, rng.Next())
	}
	lengthXor := rng.Next()

	block, err := newBlockCipher(algorithmID, derivedKey)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	if algorithmID == AlgCAST128 {
		plaintext, err = decryptCAST128CBC(block, iv, ciphertext)
	} else {
		plaintext, err = decryptBlockCBC(block, iv, ciphertext)
	}
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(clearPrefix) ^ lengthXor
	if length > uint32(len(plaintext)) {
		return nil, errors.New("missingcrypt: decoded plaintext length exceeds decrypted size")
	}

	return &InnerPayload{
		Plaintext: plaintext[:length],
		IV:        iv,
		LengthXor: lengthXor,
		PRNGKind:  prngName(headerParam, algorithmID),
	}, nil
}

// encryptInnerBlockCBC is the inverse of decryptInnerBlockCBC. It pads
// plaintext to the block boundary with 0xFF bytes and prepends the XORed
// length as a 4-byte big-endian clear prefix.
func encryptInnerBlockCBC(algorithmID AlgorithmID, headerParam uint32, derivedKey []byte, plaintext []byte) ([]byte, error) {
	spec := MustAlgorithm(algorithmID)
	rng := newMessagePRNG(headerParam, spec.ID)
	rng.Seed(headerParam)
	discard := (rng.Next() & discardMask(spec.ID)) + 1
	for range discard {
		rng.Next()
	}

	iv := make([]byte, spec.BlockSize)
	for offset := 0; offset < len(iv); offset += 4 {
		putIVWord(iv[offset:offset+4], algorithmID, rng.Next())
	}
	lengthXor := rng.Next()

	block, err := newBlockCipher(algorithmID, derivedKey)
	if err != nil {
		return nil, err
	}

	// Pad to block boundary with 0xFF; the receiver strips padding using the
	// clear-prefix length, so the pad byte value does not matter functionally.
	paddedLen := (len(plaintext) + spec.BlockSize - 1) &^ (spec.BlockSize - 1)
	padded := make([]byte, paddedLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = 0xFF
	}

	var body []byte
	if algorithmID == AlgCAST128 {
		body, err = encryptCAST128CBC(block, iv, padded)
	} else {
		body, err = encryptBlockCBC(block, iv, padded)
	}
	if err != nil {
		return nil, err
	}

	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(plaintext))^lengthXor)
	copy(out[4:], body)
	return out, nil
}

// prngName returns the name of the PRNG that would be selected for a given
// (headerParam, algorithmID) pair. Used to populate InnerPayload.PRNGKind.
func prngName(headerParam uint32, algorithmID AlgorithmID) string {
	if (headerParam+uint32(algorithmID))&1 == 1 {
		return "mt19937"
	}
	return "xor128"
}

// discardMask returns the bitmask applied to the first PRNG output to
// determine how many additional values to discard before generating the IV.
// Larger masks mean more possible discard counts, increasing the keyspace for
// algorithms that were apparently considered stronger by the client authors.
func discardMask(algorithmID AlgorithmID) uint32 {
	switch algorithmID {
	case AlgMARS, AlgTwofish:
		return 0x1F // up to 32 discards
	case AlgSerpent:
		return 0x3F // up to 64 discards
	}
	return 0x0F // up to 16 discards (default)
}

// putIVWord writes a PRNG-derived uint32 into a 4-byte IV slot. Blowfish and
// CAST-128 expect their IV words in big-endian byte order; all other ciphers
// use little-endian, matching the byte order used by the client on its native
// ARM64 architecture for little-endian integer fields.
func putIVWord(dst []byte, algorithmID AlgorithmID, value uint32) {
	switch algorithmID {
	case AlgBlowfish, AlgCAST128:
		binary.BigEndian.PutUint32(dst, value)
	default:
		binary.LittleEndian.PutUint32(dst, value)
	}
}
