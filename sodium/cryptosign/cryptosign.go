package cryptosign

// #include <stdio.h>
// #include <sodium.h>
import "C"
import "github.com/redragonx/GoSodium/sodium/support"
import "github.com/redragonx/GoSodium/sodium/scalarmult"

func SignBytes() int {
	return int(C.crypto_sign_bytes())
}

func SignSeedBytes() int {
	return int(C.crypto_sign_seedbytes())
}

func SignPublicKeyBytes() int {
	return int(C.crypto_sign_publickeybytes())
}

func SignSecretKeyBytes() int {
	return int(C.crypto_sign_secretkeybytes())
}

func SignSeedKeyPair(pkOut []byte, skOut []byte, seed []byte) int {
	return int(C.crypto_sign_seed_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0]), (*C.uchar)(&seed[0])))
}

func SignKeyPair(pkOut []byte, skOut []byte) int {
	support.CheckSize(pkOut, SignPublicKeyBytes(), "sign key pair public")
	support.CheckSize(skOut, SignSecretKeyBytes(), "sign key pair secret")
	return int(C.crypto_sign_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0])))
}

func Sign(sealedMessageOut []byte, message []byte, sk []byte) int {
	support.CheckSize(sealedMessageOut, SignBytes()+len(message), "sealed message output")
	support.CheckSize(sk, SignSecretKeyBytes(), "secret key")

	lenSealedMessageOut := (C.ulonglong)(len(sealedMessageOut))

	return int(C.crypto_sign(
		(*C.uchar)(&sealedMessageOut[0]), (*C.ulonglong)(&lenSealedMessageOut),
		(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
		(*C.uchar)(&sk[0])))
}

func SignOpen(messageOut []byte, sealedMessage []byte, pk []byte) int {
	support.CheckSize(messageOut, len(sealedMessage)-SignBytes(), "message output")
	support.CheckSize(pk, SignPublicKeyBytes(), "public key")

	lenMessageOut := (C.ulonglong)(len(messageOut))

	return int(C.crypto_sign_open(
		(*C.uchar)(&messageOut[0]), (*C.ulonglong)(&lenMessageOut),
		(*C.uchar)(&sealedMessage[0]), (C.ulonglong)(len(sealedMessage)),
		(*C.uchar)(&pk[0])))
}

func SignEd25519PKToCurve25519(curve25519PK []byte, ed25519PK []byte) int {
	support.CheckSize(curve25519PK, scalarmult.ScalarMultBytes(), "curve25519 public key output")
	support.CheckSize(ed25519PK, SignPublicKeyBytes(), "ed25519 public key")

	return int(C.crypto_sign_ed25519_pk_to_curve25519(
		(*C.uchar)(&curve25519PK[0]), (*C.uchar)(&ed25519PK[0])))
}

func SignEd25519SKToCurve25519(curve25519SK []byte, ed25519SK []byte) int {
	support.CheckSize(curve25519SK, scalarmult.ScalarMultBytes(), "curve25519 secret key output")
	support.CheckSize(ed25519SK, SignSecretKeyBytes(), "ed25519 secret key")

	return int(C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(&curve25519SK[0]), (*C.uchar)(&ed25519SK[0])))
}

func SignEd25519SKToSeed(seed []byte, sk []byte) int {
	support.CheckSize(seed, SignSeedBytes(), "seed output")
	support.CheckSize(sk, SignSecretKeyBytes(), "secret key")

	return int(C.crypto_sign_ed25519_sk_to_seed(
		(*C.uchar)(&seed[0]), (*C.uchar)(&sk[0])))
}

func SignEd25519SKToPK(pkOut []byte, sk []byte) int {
	support.CheckSize(pkOut, SignPublicKeyBytes(), "public key output")
	support.CheckSize(sk, SignSecretKeyBytes(), "secret key")

	return int(C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(&pkOut[0]), (*C.uchar)(&sk[0])))
}
