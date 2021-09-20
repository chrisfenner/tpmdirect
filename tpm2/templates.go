package tpm2

var (
	// TODO: Nicer way to provide concrete values.
	bits128 TPMKeyBits = 128
	cfb     TPMAlgID   = TPMAlgCFB
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
							AES: &bits128,
						},
						Mode: TPMUSymMode{
							AES: &cfb,
						},
					},
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgNull,
					},
					KeyBits: 2048,
				},
			},
		},
	}
)
