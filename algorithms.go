// Package missingcrypt implements the encryption and decryption scheme used by
// the game's network protocol, as recovered by reverse engineering the client
// binary. It supports ten block ciphers, several of which deviate from their
// respective standards. See the README for a full description of the wire
// format and per-algorithm deviations.
package missingcrypt

import "fmt"

// AlgorithmID is the opaque 32-bit tag embedded in every envelope header that
// identifies which block cipher was used to encrypt the inner payload.
// The values are arbitrary wire identifiers assigned by the client; they carry
// no inherent structure.
type AlgorithmID uint32

// Cipher algorithm IDs as they appear on the wire.
const (
	AlgAES128   AlgorithmID = 0x021d4314
	AlgBlowfish AlgorithmID = 0x03478caf
	AlgCamellia AlgorithmID = 0x052e3a67
	AlgCAST128  AlgorithmID = 0x048a4dfe
	AlgIDEA     AlgorithmID = 0x0951fad3
	AlgMARS     AlgorithmID = 0x0a325482
	AlgMISTY1   AlgorithmID = 0x0b46b571
	AlgSEED     AlgorithmID = 0x01e6ac1b
	AlgSerpent  AlgorithmID = 0x07fedca9
	AlgTwofish  AlgorithmID = 0x08a723ab
)

// AlgorithmSpec holds the static parameters for a supported cipher.
// KeyBytes is the number of bytes consumed from the derived auth key to form
// the cipher key; the auth key is always at least 32 bytes (the MD5 hex
// digest), so every cipher fits within it.
type AlgorithmSpec struct {
	ID        AlgorithmID `json:"id"`
	Name      string      `json:"name"`
	BlockSize int         `json:"block_size"`
	KeyBytes  int         `json:"key_bytes"`
}

// algorithmSpecs maps each wire AlgorithmID to its static parameters.
// Blowfish uses a 32-byte key (the full 32-byte auth key); all others use 16.
var algorithmSpecs = map[AlgorithmID]AlgorithmSpec{
	AlgAES128:   {ID: AlgAES128, Name: "AES-128-CBC", BlockSize: 16, KeyBytes: 16},
	AlgBlowfish: {ID: AlgBlowfish, Name: "Blowfish-CBC", BlockSize: 8, KeyBytes: 32},
	AlgCamellia: {ID: AlgCamellia, Name: "Camellia-128-CBC", BlockSize: 16, KeyBytes: 16},
	AlgCAST128:  {ID: AlgCAST128, Name: "CAST-128-CBC", BlockSize: 8, KeyBytes: 16},
	AlgIDEA:     {ID: AlgIDEA, Name: "IDEA-CBC", BlockSize: 8, KeyBytes: 16},
	AlgMARS:     {ID: AlgMARS, Name: "MARS-128-CBC", BlockSize: 16, KeyBytes: 16},
	AlgMISTY1:   {ID: AlgMISTY1, Name: "MISTY1-CBC", BlockSize: 8, KeyBytes: 16},
	AlgSEED:     {ID: AlgSEED, Name: "SEED-128-CBC", BlockSize: 16, KeyBytes: 16},
	AlgSerpent:  {ID: AlgSerpent, Name: "Serpent-128-CBC", BlockSize: 16, KeyBytes: 16},
	AlgTwofish:  {ID: AlgTwofish, Name: "Twofish-128-CBC", BlockSize: 16, KeyBytes: 16},
}

// LookupAlgorithm returns the spec for id, or (zero, false) if unknown.
func LookupAlgorithm(id AlgorithmID) (AlgorithmSpec, bool) {
	spec, ok := algorithmSpecs[id]
	return spec, ok
}

// MustAlgorithm returns the spec for id, panicking if the id is not
// recognised. Used in internal paths where an unrecognised id indicates a
// programming error rather than malformed input.
func MustAlgorithm(id AlgorithmID) AlgorithmSpec {
	spec, ok := LookupAlgorithm(id)
	if !ok {
		panic(fmt.Sprintf("unknown algorithm id %#x", uint32(id)))
	}
	return spec
}
