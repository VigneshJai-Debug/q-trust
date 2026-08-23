package main

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/rand"
)

func generateLegacy() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func weakDigest(data []byte) [16]byte {
	return md5.Sum(data)
}
