package missingcrypt

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrUnsupportedInputType = errors.New("missingcrypt: input must be []byte or base64 string")

// Encrypt accepts plaintext as either raw bytes or a base64-encoded string and
// returns the encrypted outer envelope bytes.
func Encrypt(input any, algorithmID AlgorithmID, authKey []byte, opts EncryptOptions) ([]byte, error) {
	plaintext, err := normalizeInput(input)
	if err != nil {
		return nil, err
	}
	return encryptPayload(algorithmID, authKey, plaintext, opts)
}

// Decrypt accepts an encrypted outer envelope as either raw bytes or a
// base64-encoded string and returns the decrypted inner payload bytes.
func Decrypt(input any, authKey []byte) ([]byte, error) {
	blob, err := normalizeInput(input)
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptPayload(blob, authKey)
	if err != nil {
		return nil, err
	}
	return decrypted.Inner.Plaintext, nil
}

func normalizeInput(input any) ([]byte, error) {
	switch v := input.(type) {
	case []byte:
		return append([]byte(nil), v...), nil
	case string:
		raw, err := decodeBase64String(v)
		if err != nil {
			return nil, fmt.Errorf("missingcrypt: decode base64 input: %w", err)
		}
		return raw, nil
	default:
		return nil, ErrUnsupportedInputType
	}
}

func decodeBase64String(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		raw, err := enc.DecodeString(s)
		if err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("invalid base64 string")
}
