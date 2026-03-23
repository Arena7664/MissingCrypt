package missingcrypt

import (
	"crypto/rand"
	"encoding/binary"
)

// DecryptedPayload holds both layers of a successfully decrypted message.
// Envelope is nil when the input was shorter than a full envelope (i.e. the
// blob was treated as raw plaintext; see decryptPayload).
type DecryptedPayload struct {
	Envelope *Envelope     `json:"envelope,omitempty"`
	Inner    *InnerPayload `json:"inner,omitempty"`
}

// EncryptOptions controls the optional header fields written into the envelope.
// Zero values are safe: SeedWord and RandomWord are replaced with
// cryptographically random values when they are 0; HeaderParam defaults to 0,
// which is valid and selects xor128 for most algorithm IDs.
type EncryptOptions struct {
	// HeaderParam is embedded in the envelope header and also seeds the PRNG
	// used to derive the IV. It is typically 0 for client-generated traffic.
	HeaderParam uint32 `json:"header_param"`
	// SeedWord is the 32-bit seed value encoded in bytes 0,6,12,18 of the
	// header. Its low byte also drives footer rotation.
	SeedWord uint32 `json:"seed_word"`
	// RandomWord is used to obfuscate the algorithm ID and header param fields
	// in the envelope header.
	RandomWord uint32 `json:"random_word"`
	// BigEndianHeader causes the algorithm ID, header param, magic, and version
	// words to be byte-swapped before encoding. All server-originated traffic
	// sets this flag.
	BigEndianHeader bool `json:"big_endian_header"`
}

func decryptPayload(blob []byte, authKey []byte) (*DecryptedPayload, error) {
	// Short blobs cannot contain a full ReCrypt envelope plus footer. Treat
	// them as plaintext so callers can safely handle mixed encrypted/plain
	// payloads without a hard failure.
	if len(blob) < envelopeHeaderSize+envelopeFooterSize {
		return &DecryptedPayload{
			Inner: &InnerPayload{
				Plaintext: append([]byte(nil), blob...),
			},
		}, nil
	}

	env, err := ParseEnvelope(blob)
	if err != nil {
		return nil, err
	}
	if err := VerifyFooter(blob, authKey); err != nil {
		return nil, err
	}

	inner, err := DecryptInner(env.AlgorithmID, env.HeaderParam, authKey, env.InnerPrefix, env.InnerCiphertext)
	if err != nil {
		return nil, err
	}

	return &DecryptedPayload{
		Envelope: env,
		Inner:    inner,
	}, nil
}

func encryptPayload(algorithmID AlgorithmID, authKey []byte, plaintext []byte, opts EncryptOptions) ([]byte, error) {
	seedWord := opts.SeedWord
	randomWord := opts.RandomWord
	if seedWord == 0 {
		var err error
		seedWord, err = randomUint32()
		if err != nil {
			return nil, err
		}
	}
	if randomWord == 0 {
		var err error
		randomWord, err = randomUint32()
		if err != nil {
			return nil, err
		}
	}

	innerPayload, err := EncryptInner(algorithmID, opts.HeaderParam, authKey, plaintext)
	if err != nil {
		return nil, err
	}
	return BuildEnvelope(algorithmID, opts.HeaderParam, seedWord, randomWord, innerPayload, authKey, opts.BigEndianHeader)
}

func randomUint32() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}
