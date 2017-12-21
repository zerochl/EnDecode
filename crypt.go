package endecode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	//"errors"

	//crand "crypto/rand"
	//mr "math/rand"
	//"encoding/hex"
	//"fmt"
	//"log"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	chacha20 "golang.org/x/crypto/chacha20poly1305/chacha220"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
)

type errTimeout struct {
	error
}

func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
func (errTimeout) Error() string   { return "i/o timeout" }

const (
	defaultWndSize           = 128 // default window size, in packet
	nonceSize                = 16  // magic number
	crcSize                  = 4   // 4bytes packet checksum
	cryptHeaderSize          = nonceSize + crcSize
	mtuLimit                 = 2048
)
var (
	initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}
	saltxor       = `sH3CIVoF#rWLtJo6`
)

// BlockCrypt defines encryption/decryption methods for a given byte slice.
// Notes on implementing: the data to be encrypted contains a builtin
// nonce at the first 16 bytes
type BlockCrypt interface {
	// Encrypt encrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Encrypt(dst, src []byte) []byte

	// Decrypt decrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Decrypt(dst, src []byte) []byte
}

type chacha20BlockCrypt struct {
	//Aead cipher.AEAD
	//nonce   []byte
	//ad      []byte
	key     [32]byte
	counter [16]byte
}

func NewChacha20BlockCrypt(key []byte) (BlockCrypt, error) {
	ret := new(chacha20BlockCrypt)
	ret.counter[0] = 10
	ret.counter[1] = 0x4a
	ret.counter[2] = 0x4b
	ret.counter[3] = 0x4c
	ret.counter[4] = 0x3a
	ret.counter[5] = 0x2a
	ret.counter[6] = 0x1a
	ret.counter[7] = []byte("h")[0]
	ret.counter[8] = []byte("x")[0]
	ret.counter[9] = []byte("g")[0]
	ret.counter[10] = []byte("x")[0]
	ret.counter[11] = []byte("q")[0]
	ret.counter[12] = []byte("h")[0]
	ret.counter[13] = []byte("x")[0]
	ret.counter[14] = []byte("d")[0]
	ret.counter[15] = []byte("h")[0]
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha20BlockCrypt) Encrypt(dst, src []byte) []byte {
	//result := c.Aead.Seal(nil, c.nonce[:], src, c.ad)
	//	var input [16]byte
	//	input[0] = 1
	//	input[7] = 9
	//	input[11] = 0x4a
	chacha20.XORKeyStream(dst, src, &c.counter, &c.key)
	//log.Println("encode success:", string(dst), ";len:", len(dst))
	return dst
}

func (c *chacha20BlockCrypt) Decrypt(dst, src []byte) []byte {
	//result, _ := c.Aead.Open(nil, c.nonce[:], src, c.ad)

	//	var input [16]byte
	//	input[0] = 1
	//	input[7] = 9
	//	input[11] = 0x4a
	chacha20.XORKeyStream(dst, src, &c.counter, &c.key)
	//log.Println("Decrypt success:", string(dst))
	return dst
}

type salsa20BlockCrypt struct {
	key [32]byte
}

// NewSalsa20BlockCrypt https://en.wikipedia.org/wiki/Salsa20
func NewSalsa20BlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(salsa20BlockCrypt)
	copy(c.key[:], key)
	return c, nil
}

func (c *salsa20BlockCrypt) Encrypt(dst, src []byte) []byte {
	salsa20.XORKeyStream(dst[8:], src[8:], src[:8], &c.key)
	copy(dst[:8], src[:8])
	return dst
}
func (c *salsa20BlockCrypt) Decrypt(dst, src []byte) []byte {
	salsa20.XORKeyStream(dst[8:], src[8:], src[:8], &c.key)
	copy(dst[:8], src[:8])
	return dst
}

type twofishBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTwofishBlockCrypt https://en.wikipedia.org/wiki/Twofish
func NewTwofishBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(twofishBlockCrypt)
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, twofish.BlockSize)
	c.decbuf = make([]byte, 2*twofish.BlockSize)
	return c, nil
}

func (c *twofishBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *twofishBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type tripleDESBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTripleDESBlockCrypt https://en.wikipedia.org/wiki/Triple_DES
func NewTripleDESBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(tripleDESBlockCrypt)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, des.BlockSize)
	c.decbuf = make([]byte, 2*des.BlockSize)
	return c, nil
}

func (c *tripleDESBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *tripleDESBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type cast5BlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewCast5BlockCrypt https://en.wikipedia.org/wiki/CAST-128
func NewCast5BlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(cast5BlockCrypt)
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, cast5.BlockSize)
	c.decbuf = make([]byte, 2*cast5.BlockSize)
	return c, nil
}

func (c *cast5BlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *cast5BlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type blowfishBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewBlowfishBlockCrypt https://en.wikipedia.org/wiki/Blowfish_(cipher)
func NewBlowfishBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(blowfishBlockCrypt)
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, blowfish.BlockSize)
	c.decbuf = make([]byte, 2*blowfish.BlockSize)
	return c, nil
}

func (c *blowfishBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *blowfishBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type aesBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewAESBlockCrypt https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func NewAESBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(aesBlockCrypt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, aes.BlockSize)
	c.decbuf = make([]byte, 2*aes.BlockSize)
	return c, nil
}

func (c *aesBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *aesBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type teaBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTEABlockCrypt https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
func NewTEABlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(teaBlockCrypt)
	block, err := tea.NewCipherWithRounds(key, 16)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, tea.BlockSize)
	c.decbuf = make([]byte, 2*tea.BlockSize)
	return c, nil
}

func (c *teaBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *teaBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type xteaBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewXTEABlockCrypt https://en.wikipedia.org/wiki/XTEA
func NewXTEABlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(xteaBlockCrypt)
	block, err := xtea.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, xtea.BlockSize)
	c.decbuf = make([]byte, 2*xtea.BlockSize)
	return c, nil
}

func (c *xteaBlockCrypt) Encrypt(dst, src []byte) []byte {
	encrypt(c.block, dst, src, c.encbuf)
	return dst
}
func (c *xteaBlockCrypt) Decrypt(dst, src []byte) []byte {
	decrypt(c.block, dst, src, c.decbuf)
	return dst
}

type simpleXORBlockCrypt struct {
	xortbl []byte
}

// NewSimpleXORBlockCrypt simple xor with key expanding
func NewSimpleXORBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(simpleXORBlockCrypt)
	c.xortbl = pbkdf2.Key(key, []byte(saltxor), 32, mtuLimit, sha1.New)
	return c, nil
}

func (c *simpleXORBlockCrypt) Encrypt(dst, src []byte) []byte {
	xorBytes(dst, src, c.xortbl)
	return dst
}
func (c *simpleXORBlockCrypt) Decrypt(dst, src []byte) []byte {
	xorBytes(dst, src, c.xortbl)
	return dst
}

type noneBlockCrypt struct{}

// NewNoneBlockCrypt does nothing but copying
func NewNoneBlockCrypt(key []byte) (BlockCrypt, error) {
	return new(noneBlockCrypt), nil
}

func (c *noneBlockCrypt) Encrypt(dst, src []byte) []byte {
	copy(dst, src)
	return dst
}
func (c *noneBlockCrypt) Decrypt(dst, src []byte) []byte {
	copy(dst, src)
	return dst
}

// packet encryption with local CFB mode
func encrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		xorWords(dst[base:], src[base:], tbl)
		block.Encrypt(tbl, dst[base:])
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}

func decrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	next := buf[blocksize:]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		block.Encrypt(next, src[base:])
		xorWords(dst[base:], src[base:], tbl)
		tbl, next = next, tbl
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}
