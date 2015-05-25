package cryptobox

import "github.com/redragonx/GoSodium/sodium/support"

// #include <stdio.h>
// #include <sodium.h>
import "C"

func boxSeal(cipherTextOut []byte, message []byte, pk []byte ) int {
	support.CheckSize(cipherTextOut, BoxMacBytes() + len(message), "cypher text output")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")

	return int(C.crypto_box_seal(
		(*C.uchar)(&cipherTextOut[0]),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&pk[0])))

}

func boxSealOpen(messageOut []byte, cypherText []byte, pk, sk []byte) int {
	support.CheckSize(messageOut, BoxMacBytes() + len(cypherText), "message output")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")
	support.CheckSize(sk, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_box_seal_open(
		(*C.uchar)(&messageOut[0]),
		(*C.uchar)(&cypherText[0]),
		(C.ulonglong)(len(cypherText)),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))
}

func boxSealBytes() int {
	return int(C.crypto_box_sealbytes())
}
