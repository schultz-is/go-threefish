package threefish

import (
	"encoding/binary"
	"fmt"
)

const (
	// Size of the tweak value in bytes, as expected from the user
	tweakSize int = 16

	// Constant used to ensure that key extension cannot result in all zeroes
	c240 uint64 = 0x1bd11bdaa9fc1a22
)

// Aliases to help produce concise code
var (
	loadWord  = binary.LittleEndian.Uint64
	storeWord = binary.LittleEndian.PutUint64
)

// A KeySizeError is returned when the provided key isn't the correct size.
type KeySizeError int

// Error describes a KeySizeError.
func (e KeySizeError) Error() string {
	return fmt.Sprintf("threefish: key size must be %d bytes", e)
}

// A TweakSizeError is returned when the provided tweak isn't the correct size.
type TweakSizeError struct{}

// Error describes a TweakSizeError.
func (e TweakSizeError) Error() string {
	return fmt.Sprintf("threefish: tweak size must be %d bytes", tweakSize)
}
