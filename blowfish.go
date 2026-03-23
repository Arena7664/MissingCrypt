package missingcrypt

import (
	"crypto/cipher"
	"errors"
	"unsafe"

	stdblowfish "golang.org/x/crypto/blowfish"
)

// blowfishState mirrors the unexported layout of golang.org/x/crypto/blowfish.Cipher
// so we can read and write its internal P-array and S-boxes via unsafe.Pointer.
// The layout (P [18]uint32, S0..S3 [256]uint32) has been stable across versions.
type blowfishState struct {
	P  [18]uint32  `json:"P"`
	S0 [256]uint32 `json:"S0"`
	S1 [256]uint32 `json:"S1"`
	S2 [256]uint32 `json:"S2"`
	S3 [256]uint32 `json:"S3"`
}

// blowfishInitCipher and blowfishEncryptBlock are unexported functions in
// golang.org/x/crypto/blowfish that we need to replicate the non-standard key
// schedule. go:linkname gives us access without forking the library.
//
//go:linkname blowfishInitCipher golang.org/x/crypto/blowfish.initCipher
func blowfishInitCipher(c *stdblowfish.Cipher)

//go:linkname blowfishEncryptBlock golang.org/x/crypto/blowfish.encryptBlock
func blowfishEncryptBlock(l uint32, r uint32, c *stdblowfish.Cipher) (uint32, uint32)

// newClientBlowfishCipher creates a Blowfish cipher with the game's non-standard
// key schedule. The deviation from standard Blowfish (Schneier 1993) is in how
// the key material is mixed into the P-array before the expansion loop:
//
//   - Standard: the 18-entry P-array is initialised to the Pi digits, then each
//     32-bit P entry is XORed with the corresponding 32-bit chunk of the key
//     (wrapping around the key), then the expansion encrypt loop runs over both
//     P and all four S-boxes.
//
//   - Client: initCipher sets P to the Pi digits without applying any key XOR.
//     The 72 individual bytes of P are then XORed with the key bytes (cycling
//     through the 32-byte key). The expansion encrypt loop then runs over P and
//     the four S-boxes as in the standard. No key material is ever XORed into
//     the S-boxes directly — only through the expansion loop output.
//
// The net effect is that the byte-level XOR pattern into P differs from the
// standard 32-bit-word-level XOR, producing a different expanded state.
func newClientBlowfishCipher(key []byte) (cipher.Block, error) {
	if len(key) != 32 {
		return nil, errors.New("missingcrypt: blowfish key must be 32 bytes")
	}

	// Initialise P to the Pi-digit constants with no key material applied yet.
	var block stdblowfish.Cipher
	blowfishInitCipher(&block)

	// XOR key bytes into the raw bytes of P (not as 32-bit words).
	state := (*blowfishState)(unsafe.Pointer(&block))
	pBytes := (*[18 * 4]byte)(unsafe.Pointer(&state.P[0]))
	for i := range pBytes {
		pBytes[i] ^= key[i%len(key)]
	}

	// Run the standard expansion encrypt loop over P then S0..S3.
	var l, r uint32
	for i := 0; i < len(state.P); i += 2 {
		l, r = blowfishEncryptBlock(l, r, &block)
		state.P[i], state.P[i+1] = l, r
	}
	for i := 0; i < len(state.S0); i += 2 {
		l, r = blowfishEncryptBlock(l, r, &block)
		state.S0[i], state.S0[i+1] = l, r
	}
	for i := 0; i < len(state.S1); i += 2 {
		l, r = blowfishEncryptBlock(l, r, &block)
		state.S1[i], state.S1[i+1] = l, r
	}
	for i := 0; i < len(state.S2); i += 2 {
		l, r = blowfishEncryptBlock(l, r, &block)
		state.S2[i], state.S2[i+1] = l, r
	}
	for i := 0; i < len(state.S3); i += 2 {
		l, r = blowfishEncryptBlock(l, r, &block)
		state.S3[i], state.S3[i+1] = l, r
	}

	return &block, nil
}
