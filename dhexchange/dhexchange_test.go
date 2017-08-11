package dhexchange
import(
	"fmt"
	"testing"
)
func TestDhexchange(t *testing.T) {
	var origData1 string

	G, P := Generate_G_P()
	fmt.Println("parameters have already create!")

	a_pri_key,a_pub_key := Generate_pri_pub_key(G, P)
	b_pri_key,b_pub_key := Generate_pri_pub_key(G, P)
	fmt.Println("key pairs have already create!")

	a_secret_key := Generate_secret_key(b_pub_key, a_pri_key, P)
	b_secret_key := Generate_secret_key(a_pub_key, b_pri_key, P)
	t := compare_128(a_secret_key, b_secret_key )
	if t == 0 {
	fmt.Println("secret key has already create!")
	}

	fmt.Println("please input plaintext:")
	fmt.Scanln(&origData1)

	origData := []byte(origData1)
	crypted,_ := AesEncrypt(origData, a_secret_key.Tobyte())

	fmt.Println("ciphertext is: ")
	fmt.Println(string(crypted))

	origData,_  = AesDecrypt(crypted, a_secret_key.Tobyte())
	fmt.Println("plaintext is:")
	fmt.Println(string(origData))
}
