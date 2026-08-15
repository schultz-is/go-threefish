package threefish

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
)

const (
	// Size of a 512-bit block in bytes
	blockSize512 = 64

	// Number of 64-bit words per 512-bit block
	numWords512 = blockSize512 / 8

	// Number of rounds when using a 512-bit cipher
	numRounds512 = 72
)

type cipher512 struct {
	t  [(tweakSize / 8) + 1]uint64
	ks [(numRounds512 / 4) + 1][numWords512]uint64
}

var _ cipher.Block = (*cipher512)(nil)

// New512 creates a new Threefish cipher with a block size of 512 bits.
// The key argument must be 64 bytes and the tweak argument must be 16 bytes.
func New512(key, tweak []byte) (cipher.Block, error) {
	// Length check the provided key
	if len(key) != blockSize512 {
		return nil, KeySizeError(blockSize512)
	}

	c := new(cipher512)

	// Load and extend the tweak value
	if err := calculateTweak(&c.t, tweak); err != nil {
		return nil, err
	}

	// Load and extend the key
	k := new([numWords512 + 1]uint64)
	k[numWords512] = c240
	for i := range numWords512 {
		k[i] = binary.LittleEndian.Uint64(key[i*8 : (i+1)*8])
		k[numWords512] ^= k[i]
	}

	// Calculate the key schedule
	for s := 0; s <= numRounds512/4; s++ {
		for i := range numWords512 {
			c.ks[s][i] = k[(s+i)%(numWords512+1)]
			switch i {
			case numWords512 - 3:
				c.ks[s][i] += c.t[s%3]
			case numWords512 - 2:
				c.ks[s][i] += c.t[(s+1)%3]
			case numWords512 - 1:
				c.ks[s][i] += uint64(s)
			}
		}
	}

	return c, nil
}

// BlockSize returns the block size of a 512-bit cipher.
func (c *cipher512) BlockSize() int { return blockSize512 }

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher512) Encrypt(dst, src []byte) {
	if len(src) < blockSize512 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize512 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize512], src[:blockSize512]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the input
	var b0, b1, b2, b3, b4, b5, b6, b7 uint64
	b0 = binary.LittleEndian.Uint64(src[0:8])
	b1 = binary.LittleEndian.Uint64(src[8:16])
	b2 = binary.LittleEndian.Uint64(src[16:24])
	b3 = binary.LittleEndian.Uint64(src[24:32])
	b4 = binary.LittleEndian.Uint64(src[32:40])
	b5 = binary.LittleEndian.Uint64(src[40:48])
	b6 = binary.LittleEndian.Uint64(src[48:56])
	b7 = binary.LittleEndian.Uint64(src[56:64])

	// Perform encryption rounds
	for d := 0; d < numRounds512; d += 8 {
		// Add round key
		b0 += c.ks[d/4][0]
		b1 += c.ks[d/4][1]
		b2 += c.ks[d/4][2]
		b3 += c.ks[d/4][3]
		b4 += c.ks[d/4][4]
		b5 += c.ks[d/4][5]
		b6 += c.ks[d/4][6]
		b7 += c.ks[d/4][7]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 46) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 36) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 19) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 37) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 33) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 27) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 14) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 42) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 17) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 49) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 36) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 39) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 44) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 9) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 54) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 56) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		// Add round key
		b0 += c.ks[(d/4)+1][0]
		b1 += c.ks[(d/4)+1][1]
		b2 += c.ks[(d/4)+1][2]
		b3 += c.ks[(d/4)+1][3]
		b4 += c.ks[(d/4)+1][4]
		b5 += c.ks[(d/4)+1][5]
		b6 += c.ks[(d/4)+1][6]
		b7 += c.ks[(d/4)+1][7]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 39) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 30) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 34) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 24) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 13) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 50) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 10) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 17) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 25) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 29) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 39) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 43) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3

		b0 += b1
		b1 = bits.RotateLeft64(b1, 8) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 35) ^ b2
		b4 += b5
		b5 = bits.RotateLeft64(b5, 56) ^ b4
		b6 += b7
		b7 = bits.RotateLeft64(b7, 22) ^ b6
		b0, b2, b3, b4, b6, b7 = b2, b4, b7, b6, b0, b3
	}

	// Add the final round key
	b0 += c.ks[numRounds512/4][0]
	b1 += c.ks[numRounds512/4][1]
	b2 += c.ks[numRounds512/4][2]
	b3 += c.ks[numRounds512/4][3]
	b4 += c.ks[numRounds512/4][4]
	b5 += c.ks[numRounds512/4][5]
	b6 += c.ks[numRounds512/4][6]
	b7 += c.ks[numRounds512/4][7]

	// Store the ciphertext in destination
	binary.LittleEndian.PutUint64(dst[0:8], b0)
	binary.LittleEndian.PutUint64(dst[8:16], b1)
	binary.LittleEndian.PutUint64(dst[16:24], b2)
	binary.LittleEndian.PutUint64(dst[24:32], b3)
	binary.LittleEndian.PutUint64(dst[32:40], b4)
	binary.LittleEndian.PutUint64(dst[40:48], b5)
	binary.LittleEndian.PutUint64(dst[48:56], b6)
	binary.LittleEndian.PutUint64(dst[56:64], b7)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher512) Decrypt(dst, src []byte) {
	if len(src) < blockSize512 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize512 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize512], src[:blockSize512]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the ciphertext
	var b0, b1, b2, b3, b4, b5, b6, b7 uint64
	b0 = binary.LittleEndian.Uint64(src[0:8])
	b1 = binary.LittleEndian.Uint64(src[8:16])
	b2 = binary.LittleEndian.Uint64(src[16:24])
	b3 = binary.LittleEndian.Uint64(src[24:32])
	b4 = binary.LittleEndian.Uint64(src[32:40])
	b5 = binary.LittleEndian.Uint64(src[40:48])
	b6 = binary.LittleEndian.Uint64(src[48:56])
	b7 = binary.LittleEndian.Uint64(src[56:64])

	// Subtract the final round key
	b0 -= c.ks[numRounds512/4][0]
	b1 -= c.ks[numRounds512/4][1]
	b2 -= c.ks[numRounds512/4][2]
	b3 -= c.ks[numRounds512/4][3]
	b4 -= c.ks[numRounds512/4][4]
	b5 -= c.ks[numRounds512/4][5]
	b6 -= c.ks[numRounds512/4][6]
	b7 -= c.ks[numRounds512/4][7]

	// Perform decryption rounds
	for d := numRounds512 - 1; d >= 0; d -= 8 {
		// Four rounds of permute and unmix
		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -22)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -56)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -35)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -8)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -43)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -39)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -29)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -25)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -17)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -10)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -50)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -13)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -24)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -34)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -30)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -39)
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

		// Four rounds of permute and unmix
		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -56)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -54)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -9)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -44)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -39)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -36)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -49)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -17)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -42)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -14)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -27)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -33)
		b0 -= b1

		b0, b2, b3, b4, b6, b7 = b6, b0, b7, b2, b4, b3
		b7 = bits.RotateLeft64(b7^b6, -37)
		b6 -= b7
		b5 = bits.RotateLeft64(b5^b4, -19)
		b4 -= b5
		b3 = bits.RotateLeft64(b3^b2, -36)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -46)
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
}
