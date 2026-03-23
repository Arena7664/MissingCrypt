package missingcrypt

import (
	"bytes"
	"fmt"
	"testing"
)

const (
	testServerKey  = "abcdefghijklmnopqrstuvwxy1234567"
	testDeviceUUID = "aaaaaaaa-aaaa-4aaa-8aaa-000000000000"
	testRequestID  = int64(1723456789012)
)

// roundTripPlaintexts exercises the boundary conditions that matter most for
// these ciphers: empty, a few sub-block sizes, exact 8-byte and 16-byte block
// boundaries (covering both block-size families in the suite), and a
// multi-block payload long enough to exercise more than one CBC iteration.
var roundTripPlaintexts = []struct {
	name string
	data []byte
}{
	{"empty", []byte{}},
	{"1 byte", []byte{0x42}},
	{"7 bytes", []byte("ABCDEFG")},
	{"8 bytes", []byte("ABCDEFGH")},
	{"15 bytes", []byte("ABCDEFGHIJKLMNO")},
	{"16 bytes", []byte("ABCDEFGHIJKLMNOP")},
	{"100 bytes", bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 25)},
}

// TestRoundTrip verifies that Encrypt followed by Decrypt recovers the
// original plaintext for every supported algorithm.
//
// Each algorithm sub-test is run with:
//   - headerParam 0 and 1 — together these flip (headerParam+algorithmID)&1,
//     guaranteeing that both xor128 and mt19937 are exercised for every
//     algorithm regardless of its ID parity.
//   - BigEndianHeader false and true — covering both header encoding modes;
//     the server always uses true, but the client may use either.
func TestRoundTrip(t *testing.T) {
	authKey := DeriveRequestKey(testServerKey, testRequestID, testDeviceUUID)

	for _, algID := range []AlgorithmID{
		AlgAES128,
		AlgBlowfish,
		AlgCamellia,
		AlgCAST128,
		AlgIDEA,
		AlgMARS,
		AlgMISTY1,
		AlgSEED,
		AlgSerpent,
		AlgTwofish,
	} {
		spec := MustAlgorithm(algID)
		t.Run(spec.Name, func(t *testing.T) {
			t.Parallel()

			for _, pt := range roundTripPlaintexts {
				for _, hp := range []uint32{0, 1} {
					for _, be := range []bool{false, true} {
						name := fmt.Sprintf("%s/hp=%d/bigEndian=%v", pt.name, hp, be)

						ct, err := Encrypt(pt.data, algID, authKey, EncryptOptions{
							HeaderParam:     hp,
							BigEndianHeader: be,
						})
						if err != nil {
							t.Errorf("%s: Encrypt: %v", name, err)
							continue
						}

						got, err := Decrypt(ct, authKey)
						if err != nil {
							t.Errorf("%s: Decrypt: %v", name, err)
							continue
						}

						if !bytes.Equal(pt.data, got) {
							t.Errorf("%s: plaintext mismatch:\n  got  %x\n  want %x", name, got, pt.data)
						}
					}
				}
			}
		})
	}
}

// TestRoundTripHighLevel verifies the missingCrypt struct's EncryptPayload and
// DecryptPayload methods (MARS-128-CBC, big-endian header, hardcoded server key).
func TestRoundTripHighLevel(t *testing.T) {
	mc := NewMissingCrypt(testServerKey)

	for _, pt := range roundTripPlaintexts {
		ct, err := mc.EncryptPayload(pt.data, testRequestID, testDeviceUUID)
		if err != nil {
			t.Errorf("%s: EncryptPayload: %v", pt.name, err)
			continue
		}

		got, _, err := mc.DecryptPayload(ct, testRequestID, testDeviceUUID)
		if err != nil {
			t.Errorf("%s: DecryptPayload: %v", pt.name, err)
			continue
		}

		if !bytes.Equal(pt.data, got) {
			t.Errorf("%s: plaintext mismatch:\n  got  %x\n  want %x", pt.name, got, pt.data)
		}
	}
}
