package missingcrypt

import (
	"crypto/cipher"
	"errors"
)

// decryptCAST128CBC implements the game's non-standard CAST-128 CBC decryption.
//
// The block cipher itself is standard CAST-128. The non-standard part is the
// CBC chaining: for block i > 0, the XOR material is swap_halves(ct[i-1])
// (the two 32-bit halves of the previous ciphertext block swapped) rather
// than the raw previous ciphertext block. Block 0 uses the PRNG-derived IV
// unchanged.
//
//	p[i] = std_cast128_decrypt(ct[i]) XOR xm[i]
//	xm[0] = iv (unchanged)
//	xm[i] = [ct[i-1][4:8] || ct[i-1][0:4]]  for i > 0
func decryptCAST128CBC(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	bs := block.BlockSize() // 8 for CAST-128
	if len(iv) != bs {
		return nil, errors.New("missingcrypt: invalid CBC IV length")
	}
	if len(ciphertext)%bs != 0 {
		return nil, errors.New("missingcrypt: ciphertext must be block aligned")
	}

	out := make([]byte, len(ciphertext))
	xorMat := make([]byte, bs)
	copy(xorMat, iv)

	dec := make([]byte, bs)
	for i := 0; i < len(ciphertext); i += bs {
		ct := ciphertext[i : i+bs]

		block.Decrypt(dec, ct)

		p := out[i : i+bs]
		for j := range bs {
			p[j] = dec[j] ^ xorMat[j]
		}

		copy(xorMat[0:4], ct[4:8])
		copy(xorMat[4:8], ct[0:4])
	}
	return out, nil
}

// encryptCAST128CBC is the inverse of decryptCAST128CBC.
//
//	ct[i] = std_cast128_encrypt(p[i] XOR xm[i])
//	xm[0] = iv, xm[i] = [ct[i-1][4:8] || ct[i-1][0:4]]  for i > 0
func encryptCAST128CBC(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("missingcrypt: invalid CBC IV length")
	}
	if len(plaintext)%bs != 0 {
		return nil, errors.New("missingcrypt: plaintext must be block aligned")
	}

	out := make([]byte, len(plaintext))
	xorMat := make([]byte, bs)
	copy(xorMat, iv)

	z := make([]byte, bs)
	for i := 0; i < len(plaintext); i += bs {
		p := plaintext[i : i+bs]
		ct := out[i : i+bs]

		for j := range bs {
			z[j] = p[j] ^ xorMat[j]
		}
		block.Encrypt(ct, z)

		copy(xorMat[0:4], ct[4:8])
		copy(xorMat[4:8], ct[0:4])
	}
	return out, nil
}
