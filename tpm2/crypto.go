package tpm2

import (
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
)

func rsaPub(parms *TPMSRSAParms, pub *TPM2BPublicKeyRSA) (*rsa.PublicKey, error) {
	result := rsa.PublicKey{
		N: big.NewInt(0).SetBytes(pub.Buffer),
		E: int(parms.Exponent),
	}
	// TPM considers 65537 to be the default RSA public exponent, and 0 in the parms
	// indicates so.
	if result.E == 0 {
		result.E = 65537
	}
	return &result, nil
}

// Provide a convenience function for ECDH pubkeys.
// Go's ECDH functionality does not require an implementation of crypto.PublicKey.
type ecdhPub struct {
	curve elliptic.Curve
	x, y  *big.Int
}

func eccPub(parms *TPMSECCParms, pub *TPMSECCPoint) (*ecdhPub, error) {
	curve, err := parms.CurveID.Curve()
	if err != nil {
		return nil, err
	}
	return &ecdhPub{
		curve: curve,
		x:     big.NewInt(0).SetBytes(pub.X.Buffer),
		y:     big.NewInt(0).SetBytes(pub.Y.Buffer),
	}, nil
}
