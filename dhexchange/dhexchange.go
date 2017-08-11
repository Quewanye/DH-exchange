// build Diffie-Hellman key exchange algotithm lib.

package dhexchange

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"time"
)

// we need use Uint128 since some parameters (such as p, key paris, secret key) are 128 bit long but the longest int is 64 bit. 
type Uint128 struct {
	High uint64
	Low  uint64
}

// message format send between server and client 
type DH_pac struct {
	T_type int
	G      Uint128
	P      Uint128
	//pri_key Uint128
	A_pub_key Uint128
	B_pub_key Uint128
	//secret_key Uint128
	Ciphertext []byte
	Msg        string
}

// create parameters G and P

func Generate_G_P() (G, P Uint128) {
	rand.Seed(time.Now().Unix())
	G.High = 0
	x := rand.Intn(2)
	if x == 0 {
		G.Low = 2
	} else {
		G.Low = 5
	}
	P.High = 0xffffffffffffffff
	P.Low = 0xffffffffffffff61
	return
}

// start: calculate G^n mod P

func compare_128(a, b Uint128) (r int) {
	if a.High > b.High {
		return 1
	} else if a.High == b.High {
		if a.Low > b.Low {
			return 1
		} else if a.Low == b.Low {
			return 0
		} else {
			return -1
		}
	} else {
		return -1
	}
}

func is_odd_128(a Uint128) (r uint64) {
	return (a.Low & 1)
}

func lshift_128(a *Uint128) {
	var t uint64
	t = ((*a).Low >> 63) & 1
	(*a).High = ((*a).High << 1) | t
	(*a).Low = (*a).Low << 1
}

func rshift_128(a *Uint128) {
	var t uint64
	t = ((*a).High & 1) << 63
	(*a).Low = ((*a).Low >> 1) | t
	(*a).High = (*a).High >> 1
}

func add_128_i(r *Uint128, a Uint128, b uint64) {
	var overflow uint64
	overflow = 0
	var Low uint64
	Low = a.Low + b
	if Low < a.Low || Low < b {
		overflow = 1
	}
	(*r).Low = Low
	(*r).High = a.High + overflow
}

func add_128(r *Uint128, a, b Uint128) {
	var overflow uint64
	overflow = 0
	var Low uint64
	Low = a.Low + b.Low
	if Low < a.Low || Low < b.Low {
		overflow = 1
	}
	(*r).Low = Low
	(*r).High = a.High + overflow + b.High
}

func sub_128(t *Uint128, a, b Uint128) {
	var invert_b Uint128
	invert_b.Low = ^b.Low
	invert_b.High = ^b.High
	add_128_i(&invert_b, invert_b, 1)
	add_128(t, a, invert_b)
}

func powmod(pub_key *Uint128, G, pri_key, P Uint128) {
	if compare_128(G, P) > 0 {
		sub_128(&G, G, P)
	}
	powmod_r(pub_key, G, pri_key, P)
}

func mulpow(r *Uint128, a, b, c Uint128) {
	var t, double_a, p_a Uint128
	var invert_p Uint128
	invert_p.Low = 159
	invert_p.High = 0

	(*r).Low = 0
	(*r).High = 0

	for {
		if b.Low == 0 && b.High == 0 {
			break
		}
		if is_odd_128(b) == 1 {
			sub_128(&t, c, a)

			if compare_128(*r, t) >= 0 {
				sub_128(r, *r, t)
			} else {
				add_128(r, *r, a)
			}
		}
		double_a = a
		lshift_128(&double_a)

		sub_128(&p_a, c, a)

		if compare_128(a, p_a) >= 0 {
			add_128(&a, double_a, invert_p)
		} else {
			a = double_a
		}
		rshift_128(&b)
	}
}

func powmod_r(r *Uint128, a, b, c Uint128) {
	var t, half_b Uint128
	half_b = b

	if b.High == 0 && b.Low == 1 {
		(*r) = a
		return
	}
	rshift_128(&half_b)

	powmod_r(&t, a, half_b, c)
	mulpow(&t, t, t, c)
	if is_odd_128(b) == 1 {
		mulpow(&t, t, a, c)
	}
	*r = t
}

// generate key pairs

func Generate_pri_pub_key(G, P Uint128) (pri_key, pub_key Uint128) {
	rand.Seed(time.Now().Unix())
	pri_key.High = uint64(rand.Int63n(0x0fffffffffffffff))
	pri_key.Low = uint64(rand.Int63n(0x0fffffffffffffff))

	pri_key.High = pri_key.High << 1
	pri_key.Low = pri_key.Low << 1
	rand.Seed(time.Now().Unix())
	x := uint64(rand.Intn(2))
	pri_key.High = pri_key.High | x
	rand.Seed(time.Now().Unix())
	x = uint64(rand.Intn(2))
	pri_key.Low = pri_key.Low | x

	powmod(&pub_key, G, pri_key, P)
	return
}

// generate secret key

func Generate_secret_key(pub_key, pri_key, P Uint128) (secret_key Uint128) {

	powmod(&secret_key, pub_key, pri_key, P)
	return
}


func (a Uint128) Tobyte() (r []byte) {

	r = make([]byte, 16)
	binary.BigEndian.PutUint64(r[:8], a.High)
	binary.BigEndian.PutUint64(r[8:16], a.Low)
	return
}

// AES encrypt and decrypt

func AesEncrypt(origData, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {

	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {

	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

