package threefish

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
)

const (
	// Size of a 1024-bit block in bytes
	blockSize1024 = 128

	// Number of 64-bit words per 1024-bit block
	numWords1024 = blockSize1024 / 8

	// Number of rounds when using a 1024-bit cipher
	numRounds1024 = 80
)

type cipher1024 struct {
	t  [(tweakSize / 8) + 1]uint64
	ks [(numRounds1024 / 4) + 1][numWords1024]uint64
}

var _ cipher.Block = (*cipher1024)(nil)

// New1024 creates a new Threefish cipher with a block size of 1024 bits.
// The key argument must be 128 bytes and the tweak argument must be 16 bytes.
func New1024(key, tweak []byte) (cipher.Block, error) {
	// Length check the provided key
	if len(key) != blockSize1024 {
		return nil, KeySizeError(blockSize1024)
	}

	c := new(cipher1024)

	// Load and extend the tweak value
	if err := calculateTweak(&c.t, tweak); err != nil {
		return nil, err
	}

	// Load and extend the key
	k := new([numWords1024 + 1]uint64)
	k[numWords1024] = c240
	for i := 0; i < numWords1024; i++ {
		k[i] = binary.LittleEndian.Uint64(key[i*8 : (i+1)*8])
		k[numWords1024] ^= k[i]
	}

	// Calculate the key schedule
	for s := 0; s <= numRounds1024/4; s++ {
		for i := 0; i < numWords1024; i++ {
			c.ks[s][i] = k[(s+i)%(numWords1024+1)]
			switch i {
			case numWords1024 - 3:
				c.ks[s][i] += c.t[s%3]
			case numWords1024 - 2:
				c.ks[s][i] += c.t[(s+1)%3]
			case numWords1024 - 1:
				c.ks[s][i] += uint64(s)
			}
		}
	}

	return c, nil
}

// BlockSize returns the block size of a 1024-bit cipher.
func (c *cipher1024) BlockSize() int { return blockSize1024 }

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher1024) Encrypt(dst, src []byte) {
	if len(src) < blockSize1024 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize1024 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize1024], src[:blockSize1024]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the input
	var b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 uint64
	b0 = binary.LittleEndian.Uint64(src[0:8])
	b1 = binary.LittleEndian.Uint64(src[8:16])
	b2 = binary.LittleEndian.Uint64(src[16:24])
	b3 = binary.LittleEndian.Uint64(src[24:32])
	b4 = binary.LittleEndian.Uint64(src[32:40])
	b5 = binary.LittleEndian.Uint64(src[40:48])
	b6 = binary.LittleEndian.Uint64(src[48:56])
	b7 = binary.LittleEndian.Uint64(src[56:64])
	b8 = binary.LittleEndian.Uint64(src[64:72])
	b9 = binary.LittleEndian.Uint64(src[72:80])
	b10 = binary.LittleEndian.Uint64(src[80:88])
	b11 = binary.LittleEndian.Uint64(src[88:96])
	b12 = binary.LittleEndian.Uint64(src[96:104])
	b13 = binary.LittleEndian.Uint64(src[104:112])
	b14 = binary.LittleEndian.Uint64(src[112:120])
	b15 = binary.LittleEndian.Uint64(src[120:128])

	// Perform encryption rounds
	for d := 0; d < numRounds1024; d += 8 {
		// Add round key
		b0 += c.ks[d/4][0]
		b1 += c.ks[d/4][1]
		b2 += c.ks[d/4][2]
		b3 += c.ks[d/4][3]
		b4 += c.ks[d/4][4]
		b5 += c.ks[d/4][5]
		b6 += c.ks[d/4][6]
		b7 += c.ks[d/4][7]
		b8 += c.ks[d/4][8]
		b9 += c.ks[d/4][9]
		b10 += c.ks[d/4][10]
		b11 += c.ks[d/4][11]
		b12 += c.ks[d/4][12]
		b13 += c.ks[d/4][13]
		b14 += c.ks[d/4][14]
		b15 += c.ks[d/4][15]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 24) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 13) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 8) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 47) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 8) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 17) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 22) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 37) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 38) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 19) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 10) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 55) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 49) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 18) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 23) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 52) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 33) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 4) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 51) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 13) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 34) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 41) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 59) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 17) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 5) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 20) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 48) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 41) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 47) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 28) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 16) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 25) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		// Add round key
		b0 += c.ks[(d/4)+1][0]
		b1 += c.ks[(d/4)+1][1]
		b2 += c.ks[(d/4)+1][2]
		b3 += c.ks[(d/4)+1][3]
		b4 += c.ks[(d/4)+1][4]
		b5 += c.ks[(d/4)+1][5]
		b6 += c.ks[(d/4)+1][6]
		b7 += c.ks[(d/4)+1][7]
		b8 += c.ks[(d/4)+1][8]
		b9 += c.ks[(d/4)+1][9]
		b10 += c.ks[(d/4)+1][10]
		b11 += c.ks[(d/4)+1][11]
		b12 += c.ks[(d/4)+1][12]
		b13 += c.ks[(d/4)+1][13]
		b14 += c.ks[(d/4)+1][14]
		b15 += c.ks[(d/4)+1][15]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 41) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 9) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 37) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 31) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 12) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 47) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 44) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 30) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 16) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 34) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 56) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 51) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 4) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 53) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 42) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 41) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 31) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 44) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 47) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 46) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 19) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 42) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 44) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 25) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 9) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 48) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 35) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 52) ^ b6
		b8 += b9
		b9 = bits.RotateLeft64(b9, 23) ^ b8
		b10 += b11
		b11 = bits.RotateLeft64(b11, 31) ^ b10
		b12 += b13
		b13 = bits.RotateLeft64(b13, 37) ^ b12
		b14 += b15
		b15 = bits.RotateLeft64(b15, 20) ^ b14
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b9, b13, b6, b11, b4, b15, b10, b7, b12, b3, b14, b5, b8, b1
	}

	// Add the final round key
	b0 += c.ks[numRounds1024/4][0]
	b1 += c.ks[numRounds1024/4][1]
	b2 += c.ks[numRounds1024/4][2]
	b3 += c.ks[numRounds1024/4][3]
	b4 += c.ks[numRounds1024/4][4]
	b5 += c.ks[numRounds1024/4][5]
	b6 += c.ks[numRounds1024/4][6]
	b7 += c.ks[numRounds1024/4][7]
	b8 += c.ks[numRounds1024/4][8]
	b9 += c.ks[numRounds1024/4][9]
	b10 += c.ks[numRounds1024/4][10]
	b11 += c.ks[numRounds1024/4][11]
	b12 += c.ks[numRounds1024/4][12]
	b13 += c.ks[numRounds1024/4][13]
	b14 += c.ks[numRounds1024/4][14]
	b15 += c.ks[numRounds1024/4][15]

	// Store the ciphertext in destination
	binary.LittleEndian.PutUint64(dst[0:8], b0)
	binary.LittleEndian.PutUint64(dst[8:16], b1)
	binary.LittleEndian.PutUint64(dst[16:24], b2)
	binary.LittleEndian.PutUint64(dst[24:32], b3)
	binary.LittleEndian.PutUint64(dst[32:40], b4)
	binary.LittleEndian.PutUint64(dst[40:48], b5)
	binary.LittleEndian.PutUint64(dst[48:56], b6)
	binary.LittleEndian.PutUint64(dst[56:64], b7)
	binary.LittleEndian.PutUint64(dst[64:72], b8)
	binary.LittleEndian.PutUint64(dst[72:80], b9)
	binary.LittleEndian.PutUint64(dst[80:88], b10)
	binary.LittleEndian.PutUint64(dst[88:96], b11)
	binary.LittleEndian.PutUint64(dst[96:104], b12)
	binary.LittleEndian.PutUint64(dst[104:112], b13)
	binary.LittleEndian.PutUint64(dst[112:120], b14)
	binary.LittleEndian.PutUint64(dst[120:128], b15)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher1024) Decrypt(dst, src []byte) {
	if len(src) < blockSize1024 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize1024 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize1024], src[:blockSize1024]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the ciphertext
	var b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 uint64
	b0 = binary.LittleEndian.Uint64(src[0:8])
	b1 = binary.LittleEndian.Uint64(src[8:16])
	b2 = binary.LittleEndian.Uint64(src[16:24])
	b3 = binary.LittleEndian.Uint64(src[24:32])
	b4 = binary.LittleEndian.Uint64(src[32:40])
	b5 = binary.LittleEndian.Uint64(src[40:48])
	b6 = binary.LittleEndian.Uint64(src[48:56])
	b7 = binary.LittleEndian.Uint64(src[56:64])
	b8 = binary.LittleEndian.Uint64(src[64:72])
	b9 = binary.LittleEndian.Uint64(src[72:80])
	b10 = binary.LittleEndian.Uint64(src[80:88])
	b11 = binary.LittleEndian.Uint64(src[88:96])
	b12 = binary.LittleEndian.Uint64(src[96:104])
	b13 = binary.LittleEndian.Uint64(src[104:112])
	b14 = binary.LittleEndian.Uint64(src[112:120])
	b15 = binary.LittleEndian.Uint64(src[120:128])

	// Subtract the final round key
	b0 -= c.ks[numRounds1024/4][0]
	b1 -= c.ks[numRounds1024/4][1]
	b2 -= c.ks[numRounds1024/4][2]
	b3 -= c.ks[numRounds1024/4][3]
	b4 -= c.ks[numRounds1024/4][4]
	b5 -= c.ks[numRounds1024/4][5]
	b6 -= c.ks[numRounds1024/4][6]
	b7 -= c.ks[numRounds1024/4][7]
	b8 -= c.ks[numRounds1024/4][8]
	b9 -= c.ks[numRounds1024/4][9]
	b10 -= c.ks[numRounds1024/4][10]
	b11 -= c.ks[numRounds1024/4][11]
	b12 -= c.ks[numRounds1024/4][12]
	b13 -= c.ks[numRounds1024/4][13]
	b14 -= c.ks[numRounds1024/4][14]
	b15 -= c.ks[numRounds1024/4][15]

	// Perform decryption rounds
	for d := numRounds1024 - 1; d >= 0; d -= 8 {
		// Four rounds of permute and unmix
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -20)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -37)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -31)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -23)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -52)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -35)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -48)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -9)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -25)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -44)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -42)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -19)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -46)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -47)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -44)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -31)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -41)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -42)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -53)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -4)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -51)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -56)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -34)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -16)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -30)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -44)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -47)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -12)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -31)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -37)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -9)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -41)
		b0 -= b1

		// Subtract round key
		b0 -= c.ks[d/4][0]
		b1 -= c.ks[d/4][1]
		b2 -= c.ks[d/4][2]
		b3 -= c.ks[d/4][3]
		b4 -= c.ks[d/4][4]
		b5 -= c.ks[d/4][5]
		b6 -= c.ks[d/4][6]
		b7 -= c.ks[d/4][7]
		b8 -= c.ks[d/4][8]
		b9 -= c.ks[d/4][9]
		b10 -= c.ks[d/4][10]
		b11 -= c.ks[d/4][11]
		b12 -= c.ks[d/4][12]
		b13 -= c.ks[d/4][13]
		b14 -= c.ks[d/4][14]
		b15 -= c.ks[d/4][15]

		// Four rounds of permute and unmix
		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -25)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -16)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -28)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -47)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -41)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -48)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -20)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -5)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -17)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -59)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -41)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -34)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -13)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -51)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -4)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -33)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -52)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -23)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -18)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -49)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -55)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -10)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -19)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -38)
		b0 -= b1

		b1, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 =
			b15, b11, b6, b13, b4, b9, b14, b1, b8, b5, b10, b3, b12, b7
		b15 = bits.RotateLeft64(b15^b14, -37)
		b14 -= b15
		b13 = bits.RotateLeft64(b13^b12, -22)
		b12 -= b13
		b11 = bits.RotateLeft64(b11^b10, -17)
		b10 -= b11
		b9 = bits.RotateLeft64(b9^b8, -8)
		b8 -= b9
		b7 = bits.RotateLeft64(b7^b6, -47)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -8)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -13)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -24)
		b0 -= b1

		// Subtract round key
		b0 -= c.ks[(d/4)-1][0]
		b1 -= c.ks[(d/4)-1][1]
		b2 -= c.ks[(d/4)-1][2]
		b3 -= c.ks[(d/4)-1][3]
		b4 -= c.ks[(d/4)-1][4]
		b5 -= c.ks[(d/4)-1][5]
		b6 -= c.ks[(d/4)-1][6]
		b7 -= c.ks[(d/4)-1][7]
		b8 -= c.ks[(d/4)-1][8]
		b9 -= c.ks[(d/4)-1][9]
		b10 -= c.ks[(d/4)-1][10]
		b11 -= c.ks[(d/4)-1][11]
		b12 -= c.ks[(d/4)-1][12]
		b13 -= c.ks[(d/4)-1][13]
		b14 -= c.ks[(d/4)-1][14]
		b15 -= c.ks[(d/4)-1][15]
	}

	// Store decrypted value in destination
	binary.LittleEndian.PutUint64(dst[0:8], b0)
	binary.LittleEndian.PutUint64(dst[8:16], b1)
	binary.LittleEndian.PutUint64(dst[16:24], b2)
	binary.LittleEndian.PutUint64(dst[24:32], b3)
	binary.LittleEndian.PutUint64(dst[32:40], b4)
	binary.LittleEndian.PutUint64(dst[40:48], b5)
	binary.LittleEndian.PutUint64(dst[48:56], b6)
	binary.LittleEndian.PutUint64(dst[56:64], b7)
	binary.LittleEndian.PutUint64(dst[64:72], b8)
	binary.LittleEndian.PutUint64(dst[72:80], b9)
	binary.LittleEndian.PutUint64(dst[80:88], b10)
	binary.LittleEndian.PutUint64(dst[88:96], b11)
	binary.LittleEndian.PutUint64(dst[96:104], b12)
	binary.LittleEndian.PutUint64(dst[104:112], b13)
	binary.LittleEndian.PutUint64(dst[112:120], b14)
	binary.LittleEndian.PutUint64(dst[120:128], b15)
}
