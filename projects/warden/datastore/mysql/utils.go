package datastore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
)

// ScrambleCachingSha2Password computes the hash of the password using SHA256 as required by
// caching_sha2_password plugin for "fast" authentication
func ScrambleCachingSha2Password(salt []byte, password []byte) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA256(password)
	crypt := sha256.New()
	crypt.Write(password)
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA256(SHA256(stage1Hash) + salt)
	crypt.Reset()
	crypt.Write(stage1)
	innerHash := crypt.Sum(nil)

	crypt.Reset()
	crypt.Write(innerHash)
	crypt.Write(salt)
	scramble := crypt.Sum(nil)

	// token = stage1Hash XOR scrambleHash
	for i := range stage1 {
		stage1[i] ^= scramble[i]
	}

	return stage1
}

// EncryptPasswordWithPublicKey obfuscates the password and encrypts it with server's public key as required by
// caching_sha2_password plugin for "full" authentication
func EncryptPasswordWithPublicKey(salt []byte, password []byte, pub *rsa.PublicKey) ([]byte, error) {
	if len(password) == 0 {
		return nil, nil
	}

	buffer := make([]byte, len(password)+1)
	copy(buffer, password)
	for i := range buffer {
		buffer[i] ^= salt[i%len(salt)]
	}

	sha1Hash := sha1.New()
	enc, err := rsa.EncryptOAEP(sha1Hash, rand.Reader, pub, buffer, nil)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

// ScrambleMysqlNativePassword computes the hash of the password using 4.1+ method.
//
// This can be used for example inside a `mysql_native_password` plugin implementation
// if the backend storage implements storage of plain text passwords.
func ScrambleMysqlNativePassword(salt, password []byte) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA1(password)
	crypt := sha1.New()
	crypt.Write(password)
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA1(salt + SHA1(stage1Hash))
	// inner Hash
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)
	// outer Hash
	crypt.Reset()
	crypt.Write(salt)
	crypt.Write(hash)
	scramble := crypt.Sum(nil)

	// token = scrambleHash XOR stage1Hash
	for i := range scramble {
		scramble[i] ^= stage1[i]
	}
	return scramble
}
