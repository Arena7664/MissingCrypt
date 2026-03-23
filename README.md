# MissingCrypt

A go reimplementation of a specific SQ*XEncryptionLib

The scheme wraps each payload in a structured envelope that carries an
obfuscated algorithm identifier, a PRNG-derived IV, a masked plaintext length,
and an authentication footer. Ten block ciphers are supported, several with
deviations from their respective standards.

---

## Envelope Format

A complete message on the wire is:

```
[ 24-byte header ][ 4-byte clear prefix ][ CBC ciphertext ][ 32-byte footer ]
```

### Header (24 bytes)

The header is not laid out sequentially. It is a 6-column × 4-row matrix stored
in row-major order (i.e. the byte at position `row*6 + col`). Each column holds
one logical field, interleaved across rows:

| Column | Byte positions | Field                  | Encoding                                |
| ------ | -------------- | ---------------------- | --------------------------------------- |
| 0      | 0, 6, 12, 18   | Seed word              | Raw little-endian uint32                |
| 1      | 1, 7, 13, 19   | Version word (`0x112`) | `rol32(version XOR seed, seed)`         |
| 2      | 2, 8, 14, 20   | Random word            | Bitwise-NOT; byte order: bits 16,0,8,24 |
| 3      | 3, 9, 15, 21   | Algorithm ID           | `algorithmID XOR randomWord`            |
| 4      | 4, 10, 16, 22  | Header param           | `headerParam XOR bswap32(randomWord)`   |
| 5      | 5, 11, 17, 23  | Magic (`0xABBAABBA`)   | `ror32(magic XOR seed, seed)`           |

`blob[0]` is the low byte of the seed word and is referred to as the **seed
byte** throughout the protocol. It drives footer rotation and is always
immediately accessible without any decoding.

**Big-endian header mode**: When `BigEndianHeader` is true (always the case for
server-originated traffic) the algorithm ID, header param, magic, and version
words are byte-swapped before the masking operations above. The decoder must
byte-swap the recovered values after unmasking.

### Inner Payload

The 4-byte **clear prefix** holds the true plaintext length XORed with a
PRNG-derived mask:

```
clearPrefix = bigEndian32(len(plaintext) XOR lengthXor)
```

It is followed by the CBC ciphertext. The plaintext is padded to the cipher's
block boundary with `0xFF` bytes before encryption; the receiver uses the
recovered length to strip the padding.

### Footer (32 bytes)

The footer immediately follows the ciphertext and authenticates the entire
message up to that point (header + inner payload). See
[Footer Authentication](#footer-authentication) below.

---

## Key Derivation

```
authKey = hex( MD5( serverKey || decimal(requestTimestampMS) || deviceUUID ) )
```

`requestTimestampMS` is a 64-bit integer formatted as a decimal string. The
16-byte MD5 digest is hex-encoded to produce a 32-byte ASCII key. This key
serves double duty:

- **Cipher key**: the first `keyBytes` bytes are used as the block cipher key
  (16 bytes for most algorithms, 32 bytes for Blowfish).
- **Auth key**: all 32 bytes are used in the footer MAC.

---

## Footer Authentication

The footer is a non-standard HMAC-SHA256 that deviates from RFC 2104 in two
ways:

1. **Reversed pad order**: the outer pad (`opad`, key bytes XOR `0x5C`) is
   applied in the first hash pass, and the inner pad (`ipad`, key bytes XOR
   `0x36`) is applied in the second. Standard HMAC uses the inner pad first.

   ```
   stage1 = SHA256( opad || body )
   stage2 = SHA256( ipad || stage1 )
   ```

2. **Per-word rotation**: after hashing, each of the eight 32-bit words in the
   32-byte digest is rotated by the seed byte. If the LSB of the seed byte is 0
   the rotation is right (`ror32`); if it is 1 the rotation is left (`rol32`).

The seed byte is `blob[0]`, always accessible without decoding the header. The
MAC therefore varies with the seed even for identical body content.

---

## PRNG Selection and IV Derivation

Each message uses one of two PRNGs to derive the IV and length mask. The choice
depends on the parity of `headerParam + algorithmID`:

| `(headerParam + algorithmID) & 1` | PRNG selected |
| --------------------------------- | ------------- |
| `0` (even)                        | Xorshift-128  |
| `1` (odd)                         | MT19937       |

Both generators are seeded with `headerParam`.

### IV derivation sequence

After seeding, the PRNG output is consumed in this order:

1. **Discard count**: `discard = (rng.Next() & discardMask) + 1`
2. **Discard loop**: `rng.Next()` is called `discard` times and the output is
   thrown away.
3. **IV words**: `blockSize / 4` successive `rng.Next()` values are written into
   the IV. For Blowfish and CAST-128 each word is stored big-endian; for all
   other ciphers little-endian.
4. **Length mask**: `lengthXor = rng.Next()`

The discard mask varies by algorithm to increase the effective per-message
keyspace:

| Algorithm     | Discard mask | Max discards |
| ------------- | ------------ | ------------ |
| MARS, Twofish | `0x1F`       | 32           |
| Serpent       | `0x3F`       | 64           |
| All others    | `0x0F`       | 16           |

### Xorshift-128

Standard Marsaglia xorshift with 128-bit state. The single-seed initialisation
uses the MT multiplier `0x6C078965` to expand the 32-bit seed into four 32-bit
state words (same step function as MT19937 seeding).

### MT19937

Standard Mersenne Twister with the reference seeding, twist, and tempering
parameters. No deviations.

---

## Algorithm Deviations

### AES-128-CBC

Standard. Uses `crypto/aes` from the Go standard library with a 16-byte key.

---

### Blowfish-CBC

**Non-standard key schedule.** The deviation is in how key material is mixed
into the P-array before the expansion loop:

- **Standard** (Schneier 1993): the 18-word P-array is initialised to the Pi
  digits, then each P word is XORed with the corresponding 4-byte chunk of the
  key (cycling through the key), then the expansion-encrypt loop runs over P
  followed by all four S-boxes.

- **Client**: `initCipher` loads Pi digits into P with no key XOR applied. The
  72 **bytes** of the P-array are then XORed with the key bytes (cycling through
  the 32-byte key one byte at a time). The expansion-encrypt loop then runs
  normally over P and S0–S3.

The key difference is byte-level vs 32-bit-word-level XOR into P. Because
Blowfish operates on 32-bit words internally the byte-level XOR produces a
different initial P-array than the standard word-level XOR.

A 32-byte key is used (the full auth key), rather than the 16 bytes used by most
other algorithms.

---

### Camellia-128-CBC

Standard. Uses `github.com/enceve/crypto/camellia`.

---

### CAST-128-CBC

**Non-standard CBC chaining.** The block cipher itself is standard CAST-128
(`golang.org/x/crypto/cast5`). Only the CBC chaining mode deviates:

- **Standard CBC**: `p[i] = decrypt(ct[i]) XOR ct[i-1]` (block 0 uses the IV).
- **Client CBC**: for blocks after block 0, the XOR material is the **halves-
  swapped** previous ciphertext block rather than the raw previous block:

  ```
  p[i] = decrypt(ct[i]) XOR xm[i]
  xm[0] = iv
  xm[i] = ct[i-1][4:8] || ct[i-1][0:4]   for i > 0
  ```

This means the 8-byte CAST-128 block is treated as two 4-byte halves that are
exchanged before being used as the XOR material.

IV words for CAST-128 are stored big-endian.

---

### IDEA-CBC

Standard. Hand-rolled implementation (no Go library provides IDEA). The
algorithm matches the published Lai/Massey 1991 specification exactly. 8-byte
blocks, 16-byte key.

---

### MARS-128-CBC

Standard. Uses `github.com/deatil/go-cryptobin/cipher/mars2`.

---

### MISTY1-CBC

Standard. Uses `github.com/deatil/go-cryptobin/cipher/misty1`.

---

### SEED-128-CBC

**Non-standard key schedule, block I/O, and round structure.** Three deviations
from RFC 4269:

1. **Key schedule T1 sign**: the standard computes `T1 = K1 - K3 + RC`; the
   client computes `T1 = K1 + K3 + RC` (addition instead of subtraction for the
   third key word).

2. **Block I/O byte order**: the client always uses big-endian byte order for
   both reading the plaintext block and writing the ciphertext block, whereas
   the standard uses a different (little-endian) convention.

3. **Feistel state rotation**: the four-word Feistel state advances as
   `(v5, v7, res, v9) → (res, v9, ...)` with F applied to `(res, v9)`, rather
   than the standard `(L0, R0) → (R0, L0)` Feistel swap.

The G function uses standard SEED SS0–SS3 tables (RFC 4269 Appendix A) applied
in a single pass directly to the current state word. Because all observed
traffic uses `BigEndianHeader = true`, the client effectively absorbs a
`bswap32` into the table lookup, so no explicit byte-swap is needed at call
sites.

---

### Serpent-128-CBC

Standard. Uses `github.com/enceve/crypto/serpent`.

---

### Twofish-128-CBC

**Non-standard MDS column-2 table and subkey generation.** The Feistel round
structure, key size, and I/O format are identical to standard Twofish; only the
key-schedule computation deviates.

The standard Twofish MDS column-2 multiply produces:

```
col2(q) = [mul5B(q), mulEF(q), q, mulEF(q)]   (four bytes, LE)
```

The client replaces column 2 with an integer-add variant:

```
col2_game(q) = (uint32(mul5B(q)) + uint32(q)) | uint32(mulEF(q))<<8 | uint32(mulEF(q))<<24
             = [mul5B(q)+q (with carry into byte1), mulEF(q)+carry, 0+carry, mulEF(q)]
```

This custom col-2 is used in two places:

1. **T-tables** (`s[2]`): the T-table for the third input byte uses `col2_game`
   instead of the standard `col2`.
2. **Subkey generation** (`k[0..39]`): the h function for 128-bit keys uses
   `col2_game` at the corresponding position.

The implementation patches the key-dependent tables in an otherwise-standard
`golang.org/x/crypto/twofish` cipher struct via `unsafe.Pointer`, reusing the
standard Feistel round function.

---

## API

### Low-level

```go
// Parse and build individual envelope layers:
env, err := missingcrypt.ParseEnvelope(blob)
footer, err := missingcrypt.ComputeFooter(authKey, body, seedByte)
err := missingcrypt.VerifyFooter(blob, authKey)
inner, err := missingcrypt.DecryptInner(algorithmID, headerParam, authKey, prefix, ciphertext)
inner, err := missingcrypt.EncryptInner(algorithmID, headerParam, authKey, plaintext)

// Key derivation:
authKey := missingcrypt.DeriveRequestKey(serverKey, requestTimestampMS, deviceUUID)
```

### Mid-level

```go
// Full encrypt/decrypt with explicit algorithm and options:
blob, err := missingcrypt.Encrypt(plaintext, missingcrypt.AlgMARS, authKey, missingcrypt.EncryptOptions{
    BigEndianHeader: true,
})
plaintext, err := missingcrypt.Decrypt(blob, authKey)
```

### High-level (server key baked in)

```go
// Uses the hardcoded server key, always AlgMARS, BigEndianHeader=true:
blob, err := missingcrypt.EncryptPayload(plaintext, requestTimestampMS, deviceUUID)
plaintext, full, err := missingcrypt.DecryptPayload(blob, requestTimestampMS, deviceUUID)
```
