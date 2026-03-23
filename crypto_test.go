package missingcrypt

import (
	"encoding/base64"
	"testing"
)

func TestDecryptPayload_WithBase64String(t *testing.T) {
	encryptedBase64 := "8IjxRxsiSeKxE4VKifC99CRb8EkALD7zENYNxpeyV6N6DamEZFK/eYLZ/f9IiJbojyh8YbPylb4wT9r8IqQ6BJAAyY1HP9qhjXvjDYYvWPv2DnQ+gQ1QQR4FBi0="
	deviceUUID := ""
	reqID := int64(1714796161808)

	payload, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	mc := NewMissingCrypt("abcdefghijklmnopqrstuvwxy1234567")
	decrypted, decryptedPayload, err := mc.DecryptPayload(payload, reqID, deviceUUID)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if decrypted == nil {
		t.Error("expected decrypted payload, got nil")
	}
	if decryptedPayload == nil {
		t.Error("expected DecryptedPayload struct, got nil")
	}

	t.Logf("Decrypted Payload: %s", decrypted)
}

// TODO: Add more test cases for the different algorithms once we have homogenous test data for each algorithm.
