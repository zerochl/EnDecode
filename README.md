# EnDecode
适用于所有GoLang程序，轻松集成各种加解密方式,字符串流媒体都莫有问题。</br>
如果你的Android或者IOS集成有GoLang，那么应用到移动端也不是不可以</br>
注意：salsa20与chacha20是谷歌推荐的移动端流加密方式，要比AES加解密速度更快，安全性差别不大
### 支持如下加密方式：aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, chacha20,none</br>
### crypt_key:可以当做是密码</br>
### crypt_salt:加盐</br>
### crypt_method:加密方式</br>
</br>

### 作者联系方式：QQ：975804495
### 疯狂的程序员群：186305789，没准你能遇到绝影大神

</br>
具体使用可以参照如下方法（作者使用的Beego）</br>

        import (
          "endecode"
          "github.com/astaxie/beego"
          "sync"
        )
        var endeInfo *endecode.EnDeInfoEntity
        var mu sync.Mutex

        func Encode(data string) ([]byte, error) {
          getEnDeInfo()
          src := []byte(data)
          result, err := endecode.Encode(src, endeInfo)
          if (nil != err) {
            return nil, err
          }
          return result, nil
        }

        func Decode(data []byte) ([]byte,error) {
          getEnDeInfo()
          result, err := endecode.Decode(data, endeInfo)
          if (nil != err) {
            return nil,err
          }
          return result,nil
        }

        func getEnDeInfo() error {
          if(nil != endeInfo){
            return nil
          }
          mu.Lock()
          defer mu.Unlock()
          if(nil != endeInfo){
            return nil
          }
          key := beego.AppConfig.String("crypt_key")
          salt := beego.AppConfig.String("crypt_salt")
          method := beego.AppConfig.String("crypt_method")
          endeInfo = &endecode.EnDeInfoEntity{method, key, salt}
          return nil
        }
