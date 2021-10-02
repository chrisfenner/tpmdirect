package tpmdirect_test

import (
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating a sealed data blob on the standard-template EK using its policy.
func TestEKPolicy(t *testing.T) {
	templates := map[string]tpm2.TPM2BPublic{
		"RSA": tpm2.RSAEKTemplate,
		"ECC": tpm2.ECCEKTemplate,
	}

	// Run the whole test for each of RSA and ECC EKs.
	for name, ekTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			ekTest(t, ekTemplate)
		})
	}
}

func ekPolicy(tpm tpm2.Interface, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecretCommand{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement},
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	rsp := tpm2.PolicySecretResponse{}
	return tpm.Execute(&cmd, &rsp)
}

func ekTest(t *testing.T, ekTemplate tpm2.TPM2BPublic) {
	tpm, err := tpmdirect.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the EK
	createEKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
		},
		InPublic: ekTemplate,
	}
	var createEKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createEKCmd, &createEKRsp); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("EK name: %x", createEKRsp.Name)
	defer func() {
		// Flush the EK
		flushEKCmd := tpm2.FlushContextCommand{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		var flushEKRsp tpm2.FlushContextResponse
		if err := tpm.Execute(&flushEKCmd, &flushEKRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Exercise the EK's auth policy (PolicySecret[RH_ENDORSEMENT])
	// by creating an object under it
	data := []byte("secrets")
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: tpm2.AuthHandle{
			Handle: createEKRsp.ObjectHandle,
			Name:   createEKRsp.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				Data: tpm2.TPM2BData{
					Buffer: data,
				},
			},
		},
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:     true,
					FixedParent:  true,
					UserWithAuth: true,
					NoDA:         true,
				},
			},
		},
	}
	var createBlobRsp tpm2.CreateResponse

	// Create the blob with policy auth, without any session encryption
	t.Run("Create", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using a separate session for decryption
	t.Run("CreateDecryptSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA1, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the policy session also for decryption
	t.Run("CreateDecrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy,
				tpm2.AESEncryption(128, tpm2.EncryptIn))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the policy session also for decryption and binding it
	t.Run("CreateDecryptBound", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Bound(createEKRsp.ObjectHandle, createEKRsp.Name, nil))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, salting and using the policy session also for decryption
	// and binding it
	t.Run("CreateDecryptSaltedBound", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Bound(createEKRsp.ObjectHandle, createEKRsp.Name, nil),
				tpm2.Salted(createEKRsp.ObjectHandle, createEKRsp.OutPublic.PublicArea))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

}
