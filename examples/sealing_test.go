package sealing_test

import (
	"bytes"
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating and unsealing a sealed data blob with a password and HMAC.
func TestUnseal(t *testing.T) {
	tpm, err := tpmdirect.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the SRK
	createSRKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.NamedPrimaryHandle(tpm2.TPMRHOwner),
		InPublic:      tpm2.RSASRKTemplate,
	}
	var createSRKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp, tpm2.PasswordAuth(nil)); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SRK name: %x", createSRKRsp.Name)
	defer func() {
		// Flush the SRK
		flushSRKCmd := tpm2.FlushContextCommand{
			FlushHandle: createSRKRsp.ObjectHandle,
		}
		var flushSRKRsp tpm2.FlushContextResponse
		if err := tpm.Execute(&flushSRKCmd, &flushSRKRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Create a sealed blob under the SRK
	data := []byte("secrets")
	// Include some trailing zeros to exercise the TPM's trimming of them from auth values.
	auth := []byte("p@ssw0rd\x00\x00")
	auth2 := []byte("p@ssw0rd")
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: tpm2.NamedHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name.Buffer,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: auth,
				},
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
				Parameters: tpm2.TPMUPublicParms{
					KeyedHashDetail: &tpm2.TPMSKeyedHashParms{
						Scheme: tpm2.TPMTKeyedHashScheme{
							Scheme: tpm2.TPMAlgNull,
						},
					},
				},
			},
		},
	}
	var createBlobRsp tpm2.CreateResponse
	if err := tpm.Execute(&createBlobCmd, &createBlobRsp, tpm2.PasswordAuth(nil)); err != nil {
		t.Fatalf("%v", err)
	}

	// Load the sealed blob
	loadBlobCmd := tpm2.LoadCommand{
		ParentHandle: tpm2.NamedHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name.Buffer,
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic:  createBlobRsp.OutPublic,
	}
	var loadBlobRsp tpm2.LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp, tpm2.PasswordAuth(nil)); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContextCommand{
			FlushHandle: loadBlobRsp.ObjectHandle,
		}
		var flushBlobRsp tpm2.FlushContextResponse
		if err := tpm.Execute(&flushBlobCmd, &flushBlobRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Unseal the blob with a password session
	t.Run("WithPassword", func(t *testing.T) {
		unsealCmd := tpm2.UnsealCommand{
			ItemHandle: tpm2.NamedHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name.Buffer,
			},
		}
		var unsealRsp tpm2.UnsealResponse
		if err := tpm.Execute(&unsealCmd, &unsealRsp, tpm2.PasswordAuth(auth)); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a use-once HMAC session
	t.Run("WithHMAC", func(t *testing.T) {
		unsealCmd := tpm2.UnsealCommand{
			ItemHandle: tpm2.NamedHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name.Buffer,
			},
		}
		var unsealRsp tpm2.UnsealResponse
		if err := tpm.Execute(&unsealCmd, &unsealRsp, tpm2.HMACAuth(tpm2.TPMAlgSHA256, 16, auth2)); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a standalone HMAC session, re-using the session.
	t.Run("WithHMACSession", func(t *testing.T) {
		sess, cleanup, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16, auth2)
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()

		unsealCmd := tpm2.UnsealCommand{
			ItemHandle: tpm2.NamedHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name.Buffer,
			},
		}
		var unsealRsp tpm2.UnsealResponse
		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp, sess); err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})
}
