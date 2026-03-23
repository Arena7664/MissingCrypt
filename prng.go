package missingcrypt

// prng is the interface satisfied by both PRNG implementations. Seed
// initialises the generator from a single 32-bit value; Next advances the
// state and returns the next 32-bit output.
type prng interface {
	Seed(seed uint32)
	Next() uint32
}

// xor128 is a Xorshift-128 PRNG (Marsaglia 2003). It is seeded using the same
// linear-congruential step as the MT19937 seeder (multiplier 0x6C078965) to
// expand a single 32-bit seed into four 32-bit state words.
type xor128 struct {
	X uint32 `json:"x"`
	Y uint32 `json:"y"`
	Z uint32 `json:"z"`
	W uint32 `json:"w"`
}

func (x *xor128) Seed(seed uint32) {
	v1 := uint32(0x6C078965) * (seed ^ (seed >> 30))
	v2 := uint32(0x6C078965)*(v1^(v1>>30)) + 1
	v3 := uint32(0x6C078965)*(v2^(v2>>30)) + 2
	x.X = v1
	x.Y = v2
	x.Z = v3
	x.W = uint32(0x6C078965)*(v3^(v3>>30)) + 3
}

// Next advances the xor128 state and returns the new W word.
func (x *xor128) Next() uint32 {
	t := x.X ^ (x.X << 11)
	x.X = x.Y
	x.Y = x.Z
	x.Z = x.W
	x.W = t ^ (t >> 8) ^ x.W ^ (x.W >> 19)
	return x.W
}

// mt19937 is a standard Mersenne Twister (MT19937) PRNG with the standard
// 32-bit seeding and tempering parameters. The game uses it verbatim.
type mt19937 struct {
	State [624]uint32 `json:"state"`
	Index int         `json:"index"`
}

// Seed initialises the MT state array using the standard MT19937 seeding
// procedure, then sets Index to 624 so the first Next call triggers a twist.
func (m *mt19937) Seed(seed uint32) {
	m.State[0] = seed
	for i := 1; i < len(m.State); i++ {
		prev := m.State[i-1]
		m.State[i] = uint32(0x6C078965)*(prev^(prev>>30)) + uint32(i)
	}
	m.Index = len(m.State)
}

// Next applies standard MT19937 tempering to the next state word and returns
// the result.
func (m *mt19937) Next() uint32 {
	if m.Index >= len(m.State) {
		m.twist()
	}
	y := m.State[m.Index]
	m.Index++
	y ^= y >> 11
	y ^= (y << 7) & 0x9D2C5680
	y ^= (y << 15) & 0xEFC60000
	y ^= y >> 18
	return y
}

// twist regenerates the full 624-word MT state array.
func (m *mt19937) twist() {
	for i := range 227 {
		y := (m.State[i] & 0x80000000) | (m.State[i+1] & 0x7ffffffe)
		m.State[i] = m.State[i+397] ^ (y >> 1)
		if m.State[i+1]&1 != 0 {
			m.State[i] ^= 0x9908B0DF
		}
	}
	for i := 227; i < 623; i++ {
		y := (m.State[i] & 0x80000000) | (m.State[i+1] & 0x7ffffffe)
		m.State[i] = m.State[i-227] ^ (y >> 1)
		if m.State[i+1]&1 != 0 {
			m.State[i] ^= 0x9908B0DF
		}
	}
	y := (m.State[623] & 0x80000000) | (m.State[0] & 0x7ffffffe)
	m.State[623] = m.State[396] ^ (y >> 1)
	if m.State[0]&1 != 0 {
		m.State[623] ^= 0x9908B0DF
	}
	m.Index = 0
}

// newMessagePRNG selects which PRNG to use for a given message. The choice is
// determined by the parity of (headerParam + algorithmID): odd → MT19937,
// even → xor128. Because both headerParam and algorithmID are typically small
// and their sum flips parity with every different combination, roughly half of
// all messages use each generator.
func newMessagePRNG(headerParam uint32, algorithmID AlgorithmID) prng {
	if (headerParam+uint32(algorithmID))&1 == 1 {
		return &mt19937{}
	}
	return &xor128{}
}
