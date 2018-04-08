package main

import (
	"crypto/sha256"
	"bytes"
)

func verifyChecksum(array []byte, expectedChecksum []byte) bool {
	var actualChecksum = checksum(array)
	return bytes.Equal(actualChecksum, expectedChecksum)
}

func checksum(bytes []byte) []byte {
	return dhash(bytes)[0:payloadChecksumLen]
}

func dhash(bytes []byte) []byte {
	hashInternal := sha256.New()
	hashInternal.Write(bytes)
	hashExternal := sha256.New()
	hashExternal.Write(hashInternal.Sum(nil))
	return hashExternal.Sum(nil)
}
