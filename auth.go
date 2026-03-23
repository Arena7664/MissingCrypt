package missingcrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var (
	ErrInvalidAuthKeyLength = errors.New("missingcrypt: auth key must be at least 32 bytes")
	ErrFooterMismatch       = errors.New("missingcrypt: footer authentication failed")
)

// ComputeFooter produces the 32-byte authentication footer appended to every
// envelope. It is a non-standard HMAC-SHA256 that differs from RFC 2104 in
// two ways:
//
//  1. The pad order is reversed: the outer pad (opad, 0x5C) is applied in the
//     first hash and the inner pad (ipad, 0x36) in the second, which is the
//     opposite of standard HMAC.
//
//  2. After hashing, each of the eight 32-bit words in the digest is rotated
//     by seed bits. If the LSB of seed is 0 the rotation is right (ror32);
//     if it is 1 the rotation is left (rol32).
//
// body is everything up to but not including the footer region. seed is
// blob[0], the low byte of the envelope seed word.
func ComputeFooter(authKey []byte, body []byte, seed byte) ([]byte, error) {
	if len(authKey) < 32 {
		return nil, ErrInvalidAuthKeyLength
	}

	var opad [32]byte
	var ipad [32]byte
	for i := range opad {
		opad[i] = authKey[i] ^ 0x5C
		ipad[i] = authKey[i] ^ 0x36
	}

	// The client hashes opad || body first, then ipad || digest.
	stage1Hasher := sha256.New()
	stage1Hasher.Write(opad[:])
	stage1Hasher.Write(body)
	stage1 := stage1Hasher.Sum(nil)

	stage2Hasher := sha256.New()
	stage2Hasher.Write(ipad[:])
	stage2Hasher.Write(stage1)
	stage2 := stage2Hasher.Sum(nil)

	// Rotate each 32-bit word of the digest by seed positions. Direction is
	// determined by the LSB of seed so that different envelopes (with
	// different seeds) produce different footers even for identical bodies.
	out := make([]byte, len(stage2))
	for i := 0; i < len(stage2); i += 4 {
		word := binary.BigEndian.Uint32(stage2[i : i+4])
		if seed&1 == 0 {
			word = ror32(word, int(seed))
		} else {
			word = rol32(word, int(seed))
		}
		binary.BigEndian.PutUint32(out[i:i+4], word)
	}

	return out, nil
}

// VerifyFooter recomputes the footer for blob and checks it against the last
// envelopeFooterSize bytes of blob. The seed byte is taken from blob[0].
func VerifyFooter(blob []byte, authKey []byte) error {
	if len(blob) < envelopeHeaderSize+envelopeFooterSize {
		return ErrEnvelopeTooShort
	}

	expected, err := ComputeFooter(authKey, blob[:len(blob)-envelopeFooterSize], blob[0])
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, blob[len(blob)-envelopeFooterSize:]) {
		return ErrFooterMismatch
	}
	return nil
}
