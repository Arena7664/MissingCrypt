package missingcrypt

// _SRVRKEY is the server-side key used by DeriveRequestKey. All observed
// server-to-client traffic uses MARS-128-CBC with BigEndianHeader=true.
type missingCrypt struct {
	ServerKey string
}

func NewMissingCrypt(serverKey string) *missingCrypt {
	return &missingCrypt{
		ServerKey: serverKey,
	}
}

// EncryptPayload encrypts payload using the server key derived from reqID and
// deviceUUID. It always uses MARS-128-CBC with a big-endian header, which is
// the configuration observed in all server-originated traffic.
func (mc *missingCrypt) EncryptPayload(payload []byte, reqID int64, deviceUUID string) ([]uint8, error) {
	authkey := DeriveRequestKey(mc.ServerKey, reqID, deviceUUID)
	enc, err := encryptPayload(AlgMARS, authkey, payload, EncryptOptions{
		BigEndianHeader: true,
	})
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// DecryptPayload decrypts a server-encrypted payload. reqID must be the
// request timestamp in milliseconds and deviceUUID the device identifier, as
// used when the corresponding request was made.
func (mc *missingCrypt) DecryptPayload(payload []byte, reqID int64, deviceUUID string) ([]byte, *DecryptedPayload, error) {
	authKey := DeriveRequestKey(mc.ServerKey, reqID, deviceUUID)

	intermediary, err := decryptPayload(payload, authKey)
	if err != nil {
		return nil, nil, WrappedError{Err: err, Msg: "failed to decrypt payload", ctx: map[string]any{
			"intermediary": intermediary,
		}}
	}

	payload = intermediary.Inner.Plaintext
	return payload, intermediary, nil
}
