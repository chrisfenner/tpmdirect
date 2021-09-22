package tpm2

import (
	"crypto/hmac"
	"encoding/binary"
)

// KDFA implements the SP800-108A-CTR KDF as decribed in Part 1, 11.4.10
func KDFA(alg TPMIAlgHash, key, label, contextU, contextV []byte, lenBytes int) []byte {
	result := make([]byte, 0, lenBytes)
	hashLen := alg.Hash().Size()
	iterations := (lenBytes + hashLen - 1) / hashLen
	for ctr := uint32(1); ctr <= uint32(iterations); ctr++ {
		mac := hmac.New(alg.Hash, key)
		binary.Write(mac, binary.BigEndian, ctr)
		mac.Write(label)
		if len(label) < 1 || label[len(label)-1] != 0x00 {
			mac.Write([]byte{0x00})
		}
		mac.Write(contextU)
		mac.Write(contextV)
		binary.Write(mac, binary.BigEndian, uint32(lenBytes*8))
		result = mac.Sum(result)
	}
	return result[:lenBytes]
}
