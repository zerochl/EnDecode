package endecode

import (
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha1"
	"sync"
	"errors"
	"reflect"
)
var mu sync.Mutex
type EnDeInfoEntity struct {
	Crypt string
	Key   string
	Salt  string
}

type EnDeCode interface {
	BlockCrypt
}

var endeCode EnDeCode

func Encode(dst []byte, endeInfo *EnDeInfoEntity) ([]byte, error) {
	err := GetCrypt(endeInfo)
	if(nil != err){
		return nil,err
	}
	result :=endeCode.Encrypt(dst,dst)
	return result,nil
}

func Decode(dst []byte, endeInfo *EnDeInfoEntity) ([]byte, error) {
	err := GetCrypt(endeInfo)
	if(nil != err){
		return nil,err
	}
	result :=endeCode.Decrypt(dst,dst)
	return result,nil
}

func GetCrypt(endeInfo *EnDeInfoEntity) (error) {
	if (reflect.ValueOf(endeInfo).IsNil()) {
		return errors.New("endeInfo is null")
	}
	//此处判断是因为如果已经有了可以不执行锁
	if (endeCode != nil) {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	//再次判断，因为如果是多线程某些现场被卡死那么下面必须再次判断
	if (endeCode != nil) {
		return nil
	}
	pass := pbkdf2.Key([]byte(endeInfo.Key), []byte(endeInfo.Salt), 4096, 32, sha1.New)
	var crypt EnDeCode
	var err error
	switch endeInfo.Crypt {
	case "tea":
		crypt, err = NewTEABlockCrypt(pass[:16])
	case "xor":
		crypt, err = NewSimpleXORBlockCrypt(pass)
	case "none":
		crypt, err = NewNoneBlockCrypt(pass)
	case "aes-128":
		crypt, err = NewAESBlockCrypt(pass[:16])
	case "aes-192":
		crypt, err = NewAESBlockCrypt(pass[:24])
	case "blowfish":
		crypt, err = NewBlowfishBlockCrypt(pass)
	case "twofish":
		crypt, err = NewTwofishBlockCrypt(pass)
	case "cast5":
		crypt, err = NewCast5BlockCrypt(pass[:16])
	case "3des":
		crypt, err = NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		crypt, err = NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		crypt, err = NewSalsa20BlockCrypt(pass)
	case "chacha20":
		crypt, err = NewChacha20BlockCrypt(pass)
	default:
		endeInfo.Crypt = "aes"
		crypt, err = NewAESBlockCrypt(pass)
	}
	if (nil != err) {
		return err
	}
	endeCode = crypt
	return nil
}
