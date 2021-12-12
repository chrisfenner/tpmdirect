package tpm2

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"github.com/chrisfenner/crypto/kbkdf"
)

// KDFA implements the SP800-108A-CTR KDF as decribed in Part 1, 11.4.10
func KDFA(alg TPMIAlgHash, key, label, contextU, contextV []byte, lenBytes int) []byte {
	context := make([]byte, 0, len(contextU)+len(contextV))
	context = append(context, contextU...)
	context = append(context, contextV...)
	hmac := func() hash.Hash { return hmac.New(alg.Hash, key) }
	return kbkdf.Counter(hmac, lenBytes, label, context)
}

// KDFe implements the SP800-56A KDF as decribed in Part 1, 11.4.10.3
func KDFe(alg TPMIAlgHash, zx, label, contextU, contextV []byte, lenBytes int) []byte {
	result := make([]byte, 0, lenBytes)
	hashLen := alg.Hash().Size()
	iterations := (lenBytes + hashLen - 1) / hashLen
	for ctr := uint32(1); ctr <= uint32(iterations); ctr++ {
		h := alg.Hash()
		binary.Write(h, binary.BigEndian, ctr)
		h.Write(zx)
		h.Write(label)
		if len(label) < 1 || label[len(label)-1] != 0x00 {
			h.Write([]byte{0x00})
		}
		h.Write(contextU)
		h.Write(contextV)
		result = h.Sum(result)
	}
	return result[:lenBytes]
}
