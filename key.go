package missingcrypt

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
)

// DeriveRequestKey produces the 32-byte auth key used for both the envelope
// footer MAC and the cipher key. The construction is:
//
//	key = hex( MD5( serverKey || requestTimestampMS || deviceUUID ) )
//
// requestTimestampMS is the request timestamp in milliseconds, formatted as a
// decimal string. The resulting MD5 digest (16 bytes) is hex-encoded to 32
// ASCII bytes, which serves as the key material.
//
// The 32-byte output is long enough for Blowfish (which uses all 32 bytes) and
// for all other ciphers (which use the first 16 bytes).
func DeriveRequestKey(serverKey string, requestTimestampMS int64, deviceUUID string) []byte {
	sum := md5.Sum([]byte(serverKey + strconv.FormatInt(requestTimestampMS, 10) + deviceUUID))
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum[:])
	return out
}
