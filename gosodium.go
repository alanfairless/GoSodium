// GoSodium is a higher level, go-ideomatic wrapper on top of the LibSodium
// library.  The functions provided here handle much of the memory allocation
// and error checking, raising panic calls in cases where a function fails. For
// low-level access to the full libsodium library use GoSodium.sodium, which
// attempts to faithfully reproduce the libsodium interface.
package gosodium

// import "github.com/redragonx/GoSodium/sodium"
import "github.com/redragonx/GoSodium/sodium/cryptobox"
import "github.com/redragonx/GoSodium/sodium/randombytes"
import "github.com/redragonx/GoSodium/sodium/secretbox"
import "fmt"

type PublicKey []byte
type SecretKey []byte
type SymmetricKey []byte
type Nonce []byte

func AllocPublicKey() PublicKey {
	return make([]byte, cryptobox.BoxPublicKeyBytes())
}

func AllocSecretKey() SecretKey {
	return make([]byte, cryptobox.BoxSecretKeyBytes())
}

func AllocSymmetricKey() SymmetricKey {
	return make([]byte, secretbox.SecretBoxKeyBytes())
}

func NewKeyPair() (PublicKey, SecretKey) {
	pk := AllocPublicKey()
	sk := AllocSecretKey()
	r := cryptobox.BoxKeyPair(pk, sk)
	if r != 0 {
		panic(fmt.Sprintf("Key pair generation failed with result %d, expected 0.", r))
	}
	return pk, sk
}

func NewBoxNonce() Nonce {
	nonce := make([]byte, cryptobox.BoxNonceBytes())
	randombytes.RandomBytes(nonce)

	return nonce
}
