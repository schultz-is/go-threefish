package threefish

import (
	"crypto/cipher"
	"math/bits"
)

const (
	// Size of a 256-bit block in bytes
	blockSize256 = 32

	// Number of 64-bit words per 256-bit block
	numWords256 = blockSize256 / 8

	// Number of rounds when using a 256-bit cipher
	numRounds256 = 72
)

type cipher256 struct {
	t  [(tweakSize / 8) + 1]uint64
	ks [(numRounds256 / 4) + 1][numWords256]uint64
}

// New256 creates a new Threefish cipher with a block size of 256 bits.
// The key argument must be 32 bytes and the tweak argument must be 16 bytes.
func New256(key, tweak []byte) (cipher.Block, error) {
	// Length check the provided key
	if len(key) != blockSize256 {
		return nil, KeySizeError(blockSize256)
	}

	c := new(cipher256)

	// Load and extend the tweak value
	if err := calculateTweak(&c.t, tweak); err != nil {
		return nil, err
	}

	// Load and extend key
	k := new([numWords256 + 1]uint64)
	k[numWords256] = c240
	for i := 0; i < numWords256; i++ {
		k[i] = loadWord(key[i*8 : (i+1)*8])
		k[numWords256] ^= k[i]
	}

	// Calculate the key schedule
	for s := 0; s <= numRounds256/4; s++ {
		for i := 0; i < numWords256; i++ {
			c.ks[s][i] = k[(s+i)%(numWords256+1)]
			switch i {
			case numWords256 - 3:
				c.ks[s][i] += c.t[s%3]
			case numWords256 - 2:
				c.ks[s][i] += c.t[(s+1)%3]
			case numWords256 - 1:
				c.ks[s][i] += uint64(s)
			}
		}
	}

	return c, nil
}

// BlockSize returns the block size of a 256-bit cipher.
func (c *cipher256) BlockSize() int { return blockSize256 }

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher256) Encrypt(dst, src []byte) {
	if len(src) < blockSize256 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize256 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize256], src[:blockSize256]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the input
	var b0, b1, b2, b3 uint64
	b0 = loadWord(src[0:8])
	b1 = loadWord(src[8:16])
	b2 = loadWord(src[16:24])
	b3 = loadWord(src[24:32])

	// Perform encryption rounds
	for d := 0; d < numRounds256; d += 8 {
		// Add round key
		b0 += c.ks[d/4][0]
		b1 += c.ks[d/4][1]
		b2 += c.ks[d/4][2]
		b3 += c.ks[d/4][3]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 14) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 16) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 52) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 57) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 23) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 40) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 5) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 37) ^ b2
		b1, b3 = b3, b1

		// Add round key
		b0 += c.ks[(d/4)+1][0]
		b1 += c.ks[(d/4)+1][1]
		b2 += c.ks[(d/4)+1][2]
		b3 += c.ks[(d/4)+1][3]

		// Four rounds of mix and permute
		b0 += b1
		b1 = bits.RotateLeft64(b1, 25) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 33) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 46) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 12) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 58) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 22) ^ b2
		b1, b3 = b3, b1

		b0 += b1
		b1 = bits.RotateLeft64(b1, 32) ^ b0
		b2 += b3
		b3 = bits.RotateLeft64(b3, 32) ^ b2
		b1, b3 = b3, b1
	}

	// Add the final round key
	b0 += c.ks[numRounds256/4][0]
	b1 += c.ks[numRounds256/4][1]
	b2 += c.ks[numRounds256/4][2]
	b3 += c.ks[numRounds256/4][3]

	// Store ciphertext in destination
	storeWord(dst[0:8], b0)
	storeWord(dst[8:16], b1)
	storeWord(dst[16:24], b2)
	storeWord(dst[24:32], b3)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher256) Decrypt(dst, src []byte) {
	if len(src) < blockSize256 {
		panic("threefish: input not full block")
	}
	if len(dst) < blockSize256 {
		panic("threefish: output not full block")
	}
	if inexactOverlap(dst[:blockSize256], src[:blockSize256]) {
		panic("threefish: invalid buffer overlap")
	}

	// Load the ciphertext
	var b0, b1, b2, b3 uint64
	b0 = loadWord(src[0:8])
	b1 = loadWord(src[8:16])
	b2 = loadWord(src[16:24])
	b3 = loadWord(src[24:32])

	// Subtract the final round key
	b0 -= c.ks[numRounds256/4][0]
	b1 -= c.ks[numRounds256/4][1]
	b2 -= c.ks[numRounds256/4][2]
	b3 -= c.ks[numRounds256/4][3]

	// Perform decryption rounds
	for d := numRounds256 - 1; d >= 0; d -= 8 {
		// Four rounds of permute and unmix
		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -32)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -32)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -22)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -58)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -12)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -46)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -33)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -25)
		b0 -= b1

		// Subtract round key
		b0 -= c.ks[d/4][0]
		b1 -= c.ks[d/4][1]
		b2 -= c.ks[d/4][2]
		b3 -= c.ks[d/4][3]

		// Four rounds of permute and unmix
		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -37)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -5)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -40)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -23)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -57)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -52)
		b0 -= b1

		b1, b3 = b3, b1
		b3 = bits.RotateLeft64(b3^b2, -16)
		b2 -= b3
		b1 = bits.RotateLeft64(b1^b0, -14)
		b0 -= b1

		// Subtract round key
		b0 -= c.ks[(d/4)-1][0]
		b1 -= c.ks[(d/4)-1][1]
		b2 -= c.ks[(d/4)-1][2]
		b3 -= c.ks[(d/4)-1][3]
	}

	// Store decrypted value in destination
	storeWord(dst[0:8], b0)
	storeWord(dst[8:16], b1)
	storeWord(dst[16:24], b2)
	storeWord(dst[24:32], b3)
}
