# go-threefish

![Tests](https://github.com/schultz-is/go-threefish/workflows/Tests/badge.svg)
[![GoDoc](https://godoc.org/github.com/schultz-is/go-threefish?status.svg)](https://pkg.go.dev/github.com/schultz-is/go-threefish)
[![Go Report Card](https://goreportcard.com/badge/github.com/schultz-is/go-threefish)](https://goreportcard.com/report/github.com/schultz-is/go-threefish)
[![License](https://img.shields.io/github/license/schultz-is/go-threefish)](./LICENSE)

Threefish is a tweakable block cipher that was developed as part of the Skein
hash function as a submission to the NIST hash function competition. Threefish
supports block sizes of 256, 512, and 1024 bits.

The full Threefish specification is available in the footnotes[^1].

Test vectors were extracted from the latest reference implementation[^2].

Encryption and decryption loops have been unrolled to contain eight rounds in
each iteration. This allows rotation constants to be embedded in the code
without being repeated. This practice is described in detail in the paper[^1]
which also provides detailed performance information.

[^1]: http://www.skein-hash.info/sites/default/files/skein1.3.pdf
[^2]: http://www.skein-hash.info/sites/default/files/NIST_CD_102610.zip

## Installation

To install as a dependency in a go project:

```console
go get -U github.com/schultz-is/go-threefish
```

## Usage

The cipher implementations in this package fulfill the `crypto/cipher`
`cipher.Block` interface. Instances returned by this library can be used with
any block ciphers modes that support 256, 512, or 1024-bit block sizes.

```go
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/schultz-is/go-threefish"
)

func main() {
	message := make([]byte, 128)
	copy(message, []byte("secret message"))

	// Assign a key. Generally this is derived from a known secret value. Often
	// a passphrase is derived using a key derivation function such as PBKDF2.
	key := make([]byte, 128)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	// Assign a tweak value. This allows customization of the block cipher as in
	// the UBI block chaining mode. Support for the tweak value is not available
	// in the block ciphers modes supported by the standard library.
	tweak := make([]byte, 16)
	_, err = rand.Read(tweak)
	if err != nil {
		panic(err)
	}

	// Instantiate and initialize a block cipher.
	block, err := threefish.New1024(key, tweak)
	if err != nil {
		panic(err)
	}

	// When using CBC mode, the IV needs to be unique but does not need to be
	// secure. For this reason, it can be prepended to the ciphertext.
	ciphertext := make([]byte, block.BlockSize()+len(message))
	iv := ciphertext[:block.BlockSize()]
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[block.BlockSize():], message)

	fmt.Printf("%x\n", ciphertext)
}
```

## Testing

Unit tests can be run and test coverage can be viewed via the provided Makefile.

```console
make test
make cover
```

## Benchmarking

Benchmarks can be run and CPU and memory profiles can be generated via the
provided Makefile.

```console
make benchmark
go tool pprof cpu.prof
go tool pprof mem.prof
```

## Performance

### 2019 MacBook Pro 2.3GHz Intel i9

```console
name                      time/op     speed
Threefish256/encrypt-16   124ns ± 0%  259MB/s ± 0%
Threefish256/decrypt-16   156ns ± 0%  206MB/s ± 0%
Threefish512/encrypt-16   338ns ± 0%  189MB/s ± 0%
Threefish512/decrypt-16   310ns ± 0%  206MB/s ± 0%
Threefish1024/encrypt-16  804ns ± 0%  159MB/s ± 0%
Threefish1024/decrypt-16  778ns ± 0%  165MB/s ± 0%
```
