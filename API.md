# API Reference

The package exposes three tiers of API. Use the highest tier that covers your
use case and drop to lower tiers only when you need direct control over
individual envelope fields.

| Tier | When to use |
|------|-------------|
| [High-level](#high-level-api) | Server traffic — fixed MARS algorithm, key derived from a server key + request metadata |
| [Mid-level](#mid-level-api) | Any algorithm, key already in hand; input can be raw bytes or base64 |
| [Low-level](#low-level-api) | Inspect or construct individual envelope layers; reuse a parsed `Envelope` for re-encryption |

---

## High-level API

### `NewMissingCrypt`

```go
func NewMissingCrypt(serverKey string) *missingCrypt
```

Returns a client bound to `serverKey`. All subsequent encrypt/decrypt calls
derive the per-request auth key as `hex(MD5(serverKey + reqID + deviceUUID))`.

---

### `(*missingCrypt).EncryptPayload`

```go
func (mc *missingCrypt) EncryptPayload(payload []byte, reqID int64, deviceUUID string) ([]uint8, error)
```

Encrypts `payload` using MARS-128-CBC with a big-endian header. `reqID` is the
request timestamp in milliseconds; `deviceUUID` is the device identifier. Both
values must match those used on the original request so the receiver can
reproduce the key.

`SeedWord` and `RandomWord` are drawn from `crypto/rand`; `HeaderParam` is 0.

**Returns** the complete envelope (header + inner payload + footer) as `[]byte`.

**Errors** — passes through any error from `encryptPayload` or from
`crypto/rand`.

---

### `(*missingCrypt).DecryptPayload`

```go
func (mc *missingCrypt) DecryptPayload(payload []byte, reqID int64, deviceUUID string) ([]byte, *DecryptedPayload, error)
```

Decrypts a server-encrypted envelope. `reqID` and `deviceUUID` must match the
values used when the request was sent.

**Returns**
- `[]byte` — the recovered plaintext.
- `*DecryptedPayload` — the full parsed envelope and inner payload metadata,
  useful for inspecting header fields or the PRNG kind.

**Errors** — returns a `WrappedError` wrapping the underlying failure. Sentinel
errors `ErrFooterMismatch` and `ErrBadHeaderMagic` can be unwrapped via
`errors.Is`.

---

## Mid-level API

### `DeriveRequestKey`

```go
func DeriveRequestKey(serverKey string, requestTimestampMS int64, deviceUUID string) []byte
```

Computes the 32-byte auth key shared between caller and receiver:

```
key = hex( MD5( serverKey || decimal(requestTimestampMS) || deviceUUID ) )
```

The 16-byte MD5 digest is hex-encoded to a 32-character ASCII string. This key
is used as both the cipher key (first 16 or 32 bytes, depending on algorithm)
and the footer MAC key.

---

### `Encrypt`

```go
func Encrypt(input any, algorithmID AlgorithmID, authKey []byte, opts EncryptOptions) ([]byte, error)
```

Encrypts `input` and returns the complete envelope. `input` may be either
`[]byte` (raw plaintext) or `string` (base64-encoded plaintext — all four
standard variants are tried in order: StdEncoding, RawStdEncoding, URLEncoding,
RawURLEncoding).

`opts` controls the envelope header fields; zero value is safe and produces a
valid envelope with random `SeedWord` and `RandomWord`.

**Errors**
- `ErrUnsupportedInputType` — `input` is neither `[]byte` nor `string`.
- `ErrInvalidAuthKeyLength` — `authKey` is shorter than 32 bytes.
- Any error from `crypto/rand` when generating random header words.

---

### `Decrypt`

```go
func Decrypt(input any, authKey []byte) ([]byte, error)
```

Decrypts an envelope and returns the plaintext. `input` accepts the same types
as `Encrypt` (raw bytes or any base64 variant).

Blobs shorter than 56 bytes (header + footer minimum) are returned as-is
without error, so callers can handle mixed encrypted/plaintext traffic without
special-casing.

**Errors**
- `ErrUnsupportedInputType` — `input` is neither `[]byte` nor `string`.
- `ErrEnvelopeTooShort` — blob is too short to contain a valid envelope.
- `ErrBadHeaderMagic` — header magic does not decode to `0xABBAABBA`.
- `ErrFooterMismatch` — footer authentication failed.
- `ErrInvalidAuthKeyLength` — `authKey` is shorter than 32 bytes.

---

## Low-level API

### `ParseEnvelope`

```go
func ParseEnvelope(blob []byte) (*Envelope, error)
```

Decodes the 24-byte interleaved header from `blob` and partitions the remaining
bytes into `InnerPrefix`, `InnerCiphertext`, and `Footer`. All slice fields in
the returned `Envelope` are independent copies of the input bytes.

Does **not** verify the footer; call `VerifyFooter` separately.

**Errors**
- `ErrEnvelopeTooShort` — `blob` is shorter than 56 bytes.
- `ErrBadHeaderMagic` — the decoded magic word is not `0xABBAABBA` in either
  byte order.

---

### `BuildEnvelope`

```go
func BuildEnvelope(
    algorithmID  AlgorithmID,
    headerParam  uint32,
    seedWord     uint32,
    randomWord   uint32,
    innerPayload []byte,
    authKey      []byte,
    bigEndianHeader bool,
) ([]byte, error)
```

Assembles a complete envelope from pre-computed parts. `innerPayload` is the
output of `EncryptInner` (4-byte clear prefix + CBC ciphertext). The footer is
computed and appended automatically.

**Errors** — `ErrInvalidAuthKeyLength` if `authKey` is shorter than 32 bytes.

---

### `ComputeFooter`

```go
func ComputeFooter(authKey []byte, body []byte, seed byte) ([]byte, error)
```

Produces the 32-byte authentication footer for `body`. `seed` is `blob[0]`
(the low byte of the envelope seed word). See the README for the precise MAC
construction.

**Errors** — `ErrInvalidAuthKeyLength` if `authKey` is shorter than 32 bytes.

---

### `VerifyFooter`

```go
func VerifyFooter(blob []byte, authKey []byte) error
```

Recomputes the footer for `blob` and checks it against the last 32 bytes.
The seed byte is taken from `blob[0]`.

**Errors**
- `ErrEnvelopeTooShort` — `blob` is shorter than 56 bytes.
- `ErrInvalidAuthKeyLength` — `authKey` is shorter than 32 bytes.
- `ErrFooterMismatch` — computed and stored footers do not match.

---

### `DecryptInner`

```go
func DecryptInner(
    algorithmID AlgorithmID,
    headerParam uint32,
    derivedKey  []byte,
    clearPrefix []byte,
    ciphertext  []byte,
) (*InnerPayload, error)
```

Recovers the plaintext from the inner CBC payload. `clearPrefix` is the 4-byte
big-endian word at `blob[24:28]`; it holds `len(plaintext) XOR lengthXor`
where `lengthXor` is derived from the per-message PRNG. `derivedKey` is
typically the auth key returned by `DeriveRequestKey`.

**Errors**
- Propagates errors from cipher initialisation (e.g. key length mismatch).
- Returns an error if the recovered plaintext length exceeds the decrypted
  buffer size, indicating a corrupted or miskeyed message.

---

### `EncryptInner`

```go
func EncryptInner(
    algorithmID AlgorithmID,
    headerParam uint32,
    derivedKey  []byte,
    plaintext   []byte,
) ([]byte, error)
```

Encrypts `plaintext` and returns `clearPrefix || ciphertext`. The plaintext is
padded to the cipher's block boundary with `0xFF` bytes; the clear prefix
stores the true length so the receiver can strip the padding.

---

### `LookupAlgorithm`

```go
func LookupAlgorithm(id AlgorithmID) (AlgorithmSpec, bool)
```

Returns the spec for `id`. The second return value is false if `id` is not one
of the ten recognised algorithm IDs.

---

### `MustAlgorithm`

```go
func MustAlgorithm(id AlgorithmID) AlgorithmSpec
```

Returns the spec for `id`, panicking if the ID is unknown. Intended for
internal paths where an unrecognised ID indicates a programming error.

---

## Types

### `AlgorithmID`

```go
type AlgorithmID uint32
```

Opaque 32-bit wire identifier for a block cipher. Use the package constants
rather than raw values.

```go
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
```

---

### `AlgorithmSpec`

```go
type AlgorithmSpec struct {
    ID        AlgorithmID
    Name      string
    BlockSize int
    KeyBytes  int
}
```

| Field | Description |
|-------|-------------|
| `ID` | Wire `AlgorithmID` value |
| `Name` | Human-readable name, e.g. `"AES-128-CBC"` |
| `BlockSize` | Cipher block size in bytes (8 or 16) |
| `KeyBytes` | Number of bytes consumed from the auth key (16, or 32 for Blowfish) |

---

### `EncryptOptions`

```go
type EncryptOptions struct {
    HeaderParam     uint32
    SeedWord        uint32
    RandomWord      uint32
    BigEndianHeader bool
}
```

All fields are optional; zero values produce a valid envelope.

| Field | Default | Description |
|-------|---------|-------------|
| `HeaderParam` | `0` | Seeds the per-message PRNG for IV derivation. `0` selects xor128 for even algorithm IDs and MT19937 for odd ones. |
| `SeedWord` | random | 32-bit seed encoded in header bytes 0,6,12,18. Its low byte drives footer rotation direction. |
| `RandomWord` | random | Obfuscates the algorithm ID and header param in the encoded header. |
| `BigEndianHeader` | `false` | When true, byte-swaps algorithm ID, header param, magic, and version before encoding. Set for all server-originated traffic. |

---

### `Envelope`

```go
type Envelope struct {
    SeedByte        byte
    HeaderWord      uint32
    BigEndianHeader bool
    AlgorithmID     AlgorithmID
    AlgorithmName   string
    HeaderParam     uint32
    RandomWord      uint32
    InnerPrefix     []byte
    InnerCiphertext []byte
    Footer          []byte
    Raw             []byte
}
```

| Field | Description |
|-------|-------------|
| `SeedByte` | Low byte of the seed word (`blob[0]`); used as the footer rotation amount |
| `HeaderWord` | Full decoded seed word (bytes 0,6,12,18 of the header) |
| `BigEndianHeader` | True if the header fields were encoded in big-endian mode |
| `AlgorithmID` | Decoded cipher algorithm ID |
| `AlgorithmName` | Human-readable name for `AlgorithmID`, empty string if unknown |
| `HeaderParam` | Decoded header parameter; seeds the per-message PRNG |
| `RandomWord` | Decoded random word; was used to obfuscate the algorithm ID and header param |
| `InnerPrefix` | 4-byte big-endian word: `len(plaintext) XOR lengthXor` |
| `InnerCiphertext` | Raw CBC ciphertext of the padded plaintext |
| `Footer` | 32-byte authentication footer |
| `Raw` | Copy of the entire original blob |

All slice fields are independent copies and are safe to use after the source
blob is discarded.

---

### `InnerPayload`

```go
type InnerPayload struct {
    Plaintext []byte
    IV        []byte
    LengthXor uint32
    PRNGKind  string
}
```

| Field | Description |
|-------|-------------|
| `Plaintext` | Recovered plaintext bytes (padding already stripped) |
| `IV` | CBC initialisation vector derived from the per-message PRNG |
| `LengthXor` | Raw PRNG word XORed with `InnerPrefix` to recover the plaintext length |
| `PRNGKind` | `"mt19937"` or `"xor128"` — which generator was used for this message |

---

### `DecryptedPayload`

```go
type DecryptedPayload struct {
    Envelope *Envelope
    Inner    *InnerPayload
}
```

`Envelope` is `nil` when the input blob was shorter than 56 bytes and was
returned as-is without parsing.

---

### `WrappedError`

```go
type WrappedError struct {
    Err error
    Msg string
}
```

Satisfies the `error` interface. `Error()` returns `"Msg: Err"`, or just `Msg`
if `Err` is nil, or just `Err.Error()` if `Msg` is empty.

Underlying sentinel errors can be tested with `errors.Is`:

```go
var we missingcrypt.WrappedError
if errors.As(err, &we) {
    if errors.Is(we.Err, missingcrypt.ErrFooterMismatch) {
        // authentication failed
    }
}
```

---

## Errors

| Sentinel | Source | Meaning |
|----------|--------|---------|
| `ErrInvalidAuthKeyLength` | `ComputeFooter`, `VerifyFooter` | `authKey` is shorter than 32 bytes |
| `ErrFooterMismatch` | `VerifyFooter` | Recomputed footer does not match stored footer |
| `ErrEnvelopeTooShort` | `ParseEnvelope`, `VerifyFooter` | Blob is too short to contain a valid envelope |
| `ErrBadHeaderMagic` | `ParseEnvelope` | Header does not decode to the expected magic word `0xABBAABBA` |
| `ErrInvalidIDEAKeyLength` | `DecryptInner`, `EncryptInner` (via `newBlockCipher`) | IDEA key is not exactly 16 bytes |
| `ErrUnsupportedInputType` | `Encrypt`, `Decrypt` | `input` argument is neither `[]byte` nor `string` |

---

## Usage Examples

### Decrypt a captured server payload

```go
mc := missingcrypt.NewMissingCrypt("your-server-key")
plaintext, details, err := mc.DecryptPayload(blob, requestTimestampMS, deviceUUID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("algorithm: %s  prng: %s\n", details.Envelope.AlgorithmName, details.Inner.PRNGKind)
fmt.Printf("plaintext: %s\n", plaintext)
```

### Re-encrypt with a different algorithm

```go
authKey := missingcrypt.DeriveRequestKey(serverKey, requestTimestampMS, deviceUUID)

// Decrypt first to recover the plaintext.
plaintext, err := missingcrypt.Decrypt(blob, authKey)
if err != nil {
    log.Fatal(err)
}

// Re-encrypt with Serpent.
ct, err := missingcrypt.Encrypt(plaintext, missingcrypt.AlgSerpent, authKey, missingcrypt.EncryptOptions{
    BigEndianHeader: true,
})
```

### Inspect envelope fields without decrypting the ciphertext

```go
env, err := missingcrypt.ParseEnvelope(blob)
if err != nil {
    log.Fatal(err)
}
if err := missingcrypt.VerifyFooter(blob, authKey); err != nil {
    log.Fatalf("authentication failed: %v", err)
}
spec, ok := missingcrypt.LookupAlgorithm(env.AlgorithmID)
if ok {
    fmt.Printf("algorithm: %s  block size: %d\n", spec.Name, spec.BlockSize)
}
fmt.Printf("header param: %#x  prng: %s\n", env.HeaderParam,
    func() string {
        if (env.HeaderParam+uint32(env.AlgorithmID))&1 == 1 { return "mt19937" }
        return "xor128"
    }())
```

### Build an envelope from scratch (re-use a parsed header)

```go
env, _ := missingcrypt.ParseEnvelope(original)
_ = missingcrypt.VerifyFooter(original, authKey)

// Re-encrypt with the same header parameters to produce a byte-identical
// envelope structure (different ciphertext since IV is PRNG-derived).
inner, err := missingcrypt.EncryptInner(env.AlgorithmID, env.HeaderParam, authKey, newPlaintext)
if err != nil {
    log.Fatal(err)
}
out, err := missingcrypt.BuildEnvelope(
    env.AlgorithmID, env.HeaderParam,
    uint32(env.SeedByte), env.RandomWord,
    inner, authKey, env.BigEndianHeader,
)
```
