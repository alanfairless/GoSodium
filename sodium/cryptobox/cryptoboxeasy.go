package cryptobox

import "github.com/redragonx/GoSodium/sodium/support"

// #include <stdio.h>
// #include <sodium.h>
import "C"

func BoxDetachedAfterNm(cipherTextOut []byte, mac []byte, message []byte, nonce, key []byte) int {
	support.CheckSize(cipherTextOut, BoxMacBytes() + len(message), "cypher text output")
	support.CheckSize(mac, BoxMacBytes(), "mac")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(key, BoxBeforeNmBytes(), "key")

	return int(C.crypto_box_detached_afternm(
		(*C.uchar)(&cipherTextOut[0]),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0])))
}

func BoxDatched(cipherTextOut []byte, mac, message []byte, nonce, pk, sk []byte) int {
	support.CheckSize(cipherTextOut, BoxMacBytes() + len(message), "cypher text output")
	support.CheckSize(mac, BoxMacBytes(), "mac")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")
	support.CheckSize(sk, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_box_detached(
		(*C.uchar)(&cipherTextOut[0]),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&pk[0])))
}

func boxOpenDetached(messageOut []byte, message []byte, mac, nonce, pk, sk []byte) int {
	support.CheckSize(messageOut, BoxMacBytes() + len(message), "cipher text output")
	support.CheckSize(mac, BoxMacBytes(), "mac")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")
	support.CheckSize(sk, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_box_detached(
		(*C.uchar)(&messageOut[0]),
		(*C.uchar)(&message[0]),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))
}

func BoxEasyDetachedAfterNm(cipherTextOut []byte, message []byte, nonce, key []byte) int {
	support.CheckSize(cipherTextOut, BoxMacBytes() + len(message), "cypher text output")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(key, BoxBeforeNmBytes(), "key")

	return int(C.crypto_box_easy_afternm(
		(*C.uchar)(&cipherTextOut[0]),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0])))
}

func BoxOpenEasyAfterNm(messageOut []byte, cypherText []byte, nonce, key []byte) int {
	support.CheckSize(messageOut, BoxMacBytes()+len(cypherText), "message output")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(key, BoxBeforeNmBytes(), "key")

	return int(C.crypto_box_open_easy_afternm(
		(*C.uchar)(&messageOut[0]),
		(*C.uchar)(&cypherText[0]),
		(C.ulonglong)(len(cypherText)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0])))
}

func BoxEasy(cypherTextOut []byte, message []byte, nonce, pk, sk []byte) int {
	support.CheckSize(cypherTextOut, BoxMacBytes() + len(message), "cypher text output")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")
	support.CheckSize(sk, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_box_easy(
		(*C.uchar)(&cypherTextOut[0]),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))
}

func BoxOpenEasy(messageOut []byte, cypherText []byte, nonce, pk, sk []byte) int {
	support.CheckSize(messageOut, BoxMacBytes()+len(cypherText), "message output")
	support.CheckSize(nonce, BoxNonceBytes(), "nonce")
	support.CheckSize(pk, BoxPublicKeyBytes(), "public key")
	support.CheckSize(sk, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_box_open_easy(
		(*C.uchar)(&messageOut[0]),
		(*C.uchar)(&cypherText[0]),
		(C.ulonglong)(len(cypherText)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))
}

