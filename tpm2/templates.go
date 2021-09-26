package tpm2

var (
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	RSASRKTemplate = TPM2BPublic{
		PublicArea: TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           true,
				Decrypt:              true,
				SignEncrypt:          false,
			},
			Parameters: TPMUPublicParms{
				RSADetail: &TPMSRSAParms{
					Symmetric: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						KeyBits: TPMUSymKeyBits{
							AES: NewTPMKeyBits(128),
						},
						Mode: TPMUSymMode{
							AES: NewTPMAlgID(TPMAlgCFB),
						},
					},
					KeyBits: 2048,
				},
			},
			Unique: TPMUPublicID{
				RSA: &TPM2BPublicKeyRSA{
					Buffer: make([]byte, 256),
				},
			},
		},
	}
	ECCSRKTemplate = TPM2BPublic{
		PublicArea: TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           true,
				Decrypt:              true,
				SignEncrypt:          false,
			},
			Parameters: TPMUPublicParms{
				ECCDetail: &TPMSECCParms{
					Symmetric: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						KeyBits: TPMUSymKeyBits{
							AES: NewTPMKeyBits(128),
						},
						Mode: TPMUSymMode{
							AES: NewTPMAlgID(TPMAlgCFB),
						},
					},
					CurveID: TPMECCNistP256,
				},
			},
			Unique: TPMUPublicID{
				ECC: &TPMSECCPoint{
					X: TPM2BECCParameter{
						Buffer: make([]byte, 32),
					},
					Y: TPM2BECCParameter{
						Buffer: make([]byte, 32),
					},
				},
			},
		},
	}
)
