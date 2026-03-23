package missingcrypt

import (
	"encoding/binary"
	"errors"
)

var ErrInvalidIDEAKeyLength = errors.New("missingcrypt: IDEA requires a 16-byte key")

// ideaCipher is a standard IDEA-128 block cipher implementation. No external
// library provides a Go IDEA implementation, so it is hand-rolled here. The
// algorithm itself matches the published IDEA specification (Lai/Massey 1991)
// exactly; there are no deviations from the standard in this implementation.
type ideaCipher struct {
	Enc [52]uint16 `json:"enc"`
	Dec [52]uint16 `json:"dec"`
}

func newIDEACipher(key []byte) (*ideaCipher, error) {
	if len(key) != 16 {
		return nil, ErrInvalidIDEAKeyLength
	}
	c := &ideaCipher{}
	c.Enc = expandIDEAKey(key)
	c.Dec = invertIDEAKey(c.Enc)
	return c, nil
}

func (c *ideaCipher) BlockSize() int { return 8 }

func (c *ideaCipher) Encrypt(dst, src []byte) {
	processIDEABlock(c.Enc[:], dst, src)
}

func (c *ideaCipher) Decrypt(dst, src []byte) {
	processIDEABlock(c.Dec[:], dst, src)
}

func expandIDEAKey(key []byte) [52]uint16 {
	var out [52]uint16
	for i := range 8 {
		out[i] = binary.BigEndian.Uint16(key[i*2 : i*2+2])
	}
	ek := out[:]
	for i, j := 0, 8; j < len(out); j++ {
		i++
		ek[i+7] = ek[i&7]<<9 | ek[(i+1)&7]>>7
		ek = ek[i&8:]
		i &= 7
	}

	return out
}

func invertIDEAKey(enc [52]uint16) [52]uint16 {
	var dec [52]uint16
	var t1, t2, t3 uint16
	var p [52]uint16
	pidx := len(p)
	ekidx := 0

	t1 = mulInv(enc[ekidx])
	ekidx++
	t2 = addInv(enc[ekidx])
	ekidx++
	t3 = addInv(enc[ekidx])
	ekidx++
	pidx--
	p[pidx] = mulInv(enc[ekidx])
	ekidx++
	pidx--
	p[pidx] = t3
	pidx--
	p[pidx] = t2
	pidx--
	p[pidx] = t1

	for i := 0; i < 7; i++ {
		t1 = enc[ekidx]
		ekidx++
		pidx--
		p[pidx] = enc[ekidx]
		ekidx++
		pidx--
		p[pidx] = t1

		t1 = mulInv(enc[ekidx])
		ekidx++
		t2 = addInv(enc[ekidx])
		ekidx++
		t3 = addInv(enc[ekidx])
		ekidx++
		pidx--
		p[pidx] = mulInv(enc[ekidx])
		ekidx++
		pidx--
		p[pidx] = t2
		pidx--
		p[pidx] = t3
		pidx--
		p[pidx] = t1
	}

	t1 = enc[ekidx]
	ekidx++
	pidx--
	p[pidx] = enc[ekidx]
	ekidx++
	pidx--
	p[pidx] = t1

	t1 = mulInv(enc[ekidx])
	ekidx++
	t2 = addInv(enc[ekidx])
	ekidx++
	t3 = addInv(enc[ekidx])
	ekidx++
	pidx--
	p[pidx] = mulInv(enc[ekidx])
	pidx--
	p[pidx] = t3
	pidx--
	p[pidx] = t2
	pidx--
	p[pidx] = t1

	copy(dec[:], p[:])
	return dec
}

func processIDEABlock(key []uint16, dst, src []byte) {
	x1 := binary.BigEndian.Uint16(src[0:2])
	x2 := binary.BigEndian.Uint16(src[2:4])
	x3 := binary.BigEndian.Uint16(src[4:6])
	x4 := binary.BigEndian.Uint16(src[6:8])
	var s2, s3 uint16

	for round := 0; round < 8; round++ {
		x1 = mul(x1, key[0])
		key = key[1:]
		x2 += key[0]
		key = key[1:]
		x3 += key[0]
		key = key[1:]
		x4 = mul(x4, key[0])
		key = key[1:]

		s3 = x3
		x3 ^= x1
		x3 = mul(x3, key[0])
		key = key[1:]
		s2 = x2

		x2 ^= x4
		x2 += x3
		x2 = mul(x2, key[0])
		key = key[1:]
		x3 += x2

		x1 ^= x2
		x4 ^= x3
		x2 ^= s3
		x3 ^= s2
	}

	o1 := mul(x1, key[0])
	key = key[1:]
	o2 := x3 + key[0]
	key = key[1:]
	o3 := x2 + key[0]
	key = key[1:]
	o4 := mul(x4, key[0])

	binary.BigEndian.PutUint16(dst[0:2], o1)
	binary.BigEndian.PutUint16(dst[2:4], o2)
	binary.BigEndian.PutUint16(dst[4:6], o3)
	binary.BigEndian.PutUint16(dst[6:8], o4)
}

func mul(a, b uint16) uint16 {
	if b == 0 {
		return 1 - a
	}
	if a == 0 {
		return 1 - b
	}
	product := uint32(a) * uint32(b)
	lo := uint16(product)
	hi := uint16(product >> 16)
	if lo < hi {
		return lo - hi + 1
	}
	return lo - hi
}

func mulInv(x uint16) uint16 {
	if x <= 1 {
		return x
	}
	t1 := uint16(0x10001 / uint32(x))
	y := uint16(0x10001 % uint32(x))
	if y == 1 {
		return 1 - t1
	}
	t0 := uint16(1)
	for y != 1 {
		q := x / y
		x = x % y
		t0 += q * t1
		if x == 1 {
			return t0
		}
		q = y / x
		y = y % x
		t1 += q * t0
	}
	return 1 - t1
}

func addInv(x uint16) uint16 {
	return uint16(-int32(x))
}
