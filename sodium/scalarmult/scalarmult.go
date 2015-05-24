package scalarmult

import "github.com/redragonx/GoSodium/sodium/cryptobox"
import "github.com/redragonx/GoSodium/sodium/support"

// #include <stdio.h>
// #include <sodium.h>
import "C"

func ScalarMultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}

func ScalarMultScalarBytes() int {
	return int(C.crypto_scalarmult_scalarbytes())
}

func ScalarMultBase(pkOut []byte, skIn []byte) int {
	support.CheckSize(pkOut, cryptobox.BoxPublicKeyBytes(), "public key")
	support.CheckSize(skIn, cryptobox.BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_scalarmult_base((*C.uchar)(&pkOut[0]), (*C.uchar)(&skIn[0])))
}
