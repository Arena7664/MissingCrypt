package missingcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/deatil/go-cryptobin/cipher/mars2"
	gcmisty1 "github.com/deatil/go-cryptobin/cipher/misty1"
	"github.com/enceve/crypto/camellia"
	"github.com/enceve/crypto/serpent"
	"golang.org/x/crypto/cast5"
)

// newBlockCipher constructs the cipher.Block for the given algorithm using
// the first spec.KeyBytes bytes of derivedKey as the cipher key.
//
// Most algorithms use their standard library implementations. The exceptions
// are Blowfish (non-standard key schedule), CAST-128 (standard block cipher
// but non-standard CBC chaining handled separately in cast128.go), SEED
// (non-standard key schedule and round function), and Twofish (non-standard
// MDS col-2 table and subkey generation). See the respective source files and
// README for details.
func newBlockCipher(algorithmID AlgorithmID, derivedKey []byte) (cipher.Block, error) {
	spec := MustAlgorithm(algorithmID)
	if len(derivedKey) < spec.KeyBytes {
		return nil, errors.New("missingcrypt: derived key too short for cipher")
	}

	key := derivedKey[:spec.KeyBytes]
	switch algorithmID {
	case AlgAES128:
		return aes.NewCipher(key)
	case AlgBlowfish:
		return newClientBlowfishCipher(key)
	case AlgCamellia:
		return camellia.NewCipher(key)
	case AlgCAST128:
		return cast5.NewCipher(key)
	case AlgIDEA:
		return newIDEACipher(key)
	case AlgMARS:
		return mars2.NewCipher(key)
	case AlgMISTY1:
		return gcmisty1.NewCipher(key)
	case AlgSEED:
		return newMcryptSeed(key), nil
	case AlgSerpent:
		return serpent.NewCipher(key)
	case AlgTwofish:
		return newMcryptTwofishCipher(key)
	default:
		return nil, errors.New("missingcrypt: unsupported cipher")
	}
}

// decryptBlockCBC performs standard CBC decryption using the standard library.
// Used for all algorithms except CAST-128, which requires a non-standard
// chaining mode (see decryptCAST128CBC).
func decryptBlockCBC(block cipher.Block, iv []byte, ciphertext []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("missingcrypt: invalid CBC IV length")
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("missingcrypt: ciphertext must be block aligned")
	}

	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

// encryptBlockCBC performs standard CBC encryption using the standard library.
// Used for all algorithms except CAST-128 (see encryptCAST128CBC).
func encryptBlockCBC(block cipher.Block, iv []byte, plaintext []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("missingcrypt: invalid CBC IV length")
	}
	if len(plaintext)%block.BlockSize() != 0 {
		return nil, errors.New("missingcrypt: plaintext must be block aligned")
	}

	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out, nil
}
