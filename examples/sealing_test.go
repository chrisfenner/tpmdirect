package sealing_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test sealing and unsealing a blob with password auth.
// Note that auth values and secrets will travel in the clear across the TPM bus.
func TestSealUnseal(t *testing.T) {
	tpm, err := tpmdirect.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the SRK
	createSRKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.ECCSRKTemplate,
	}
	var createSRKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp,
		tpm2.PasswordAuth(tpm2.PrimaryHandleName(tpm2.TPMRHOwner), nil)); err != nil {
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
	auth := []byte("p@ssw0rd")
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: createSRKRsp.ObjectHandle,
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

	// Create the blob
	t.Run("Create", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.PasswordAuth(createSRKRsp.Name.Buffer, nil)); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Load the sealed blob
	loadBlobCmd := tpm2.LoadCommand{
		ParentHandle: createSRKRsp.ObjectHandle,
		InPrivate:    createBlobRsp.OutPrivate,
		InPublic:     createBlobRsp.OutPublic,
	}
	var loadBlobRsp tpm2.LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp,
		tpm2.PasswordAuth(createSRKRsp.Name.Buffer, nil)); err != nil {
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

	// Unseal the blob
	unsealCmd := tpm2.UnsealCommand{
		ItemHandle: loadBlobRsp.ObjectHandle,
	}
	var unsealRsp tpm2.UnsealResponse
	t.Run("WithPassword", func(t *testing.T) {
		if err := tpm.Execute(&unsealCmd, &unsealRsp,
			tpm2.PasswordAuth(loadBlobRsp.Name.Buffer, auth)); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with an incorrect password session
	t.Run("WithWrongPassword", func(t *testing.T) {
		err := tpm.Execute(&unsealCmd, &unsealRsp,
			tpm2.PasswordAuth(loadBlobRsp.Name.Buffer, []byte("NotThePassword")))
		if err == nil {
			t.Errorf("want TPM_RC_BAD_AUTH, got nil")
		}
		if !errors.Is(err, tpm2.TPMRCBadAuth) {
			t.Errorf("want TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 tpm2.Fmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})
}

// Test sealing and unsealing a blob with HMAC auth and parameter encryption.
// Sensitive values during this test do not travel in the clear over the TPM bus.
func TestSealUnsealSecure(t *testing.T) {
	tpm, err := tpmdirect.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the SRK
	createSRKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.ECCSRKTemplate,
	}
	var createSRKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp,
		tpm2.PasswordAuth(tpm2.PrimaryHandleName(tpm2.TPMRHOwner), nil)); err != nil {
		t.Fatalf("%v", err)
	}
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
	srkHandle, srkPublic := createSRKRsp.ObjectHandle, createSRKRsp.OutPublic.PublicArea

	// Omitted: attestation of the SRK by the EK.
	// Alternatively: using the EK instead of the SRK for session salting.
	// These involve the EK cert, which the simulator does not have.

	// Create a sealed blob under the SRK
	data := []byte("secrets")
	auth := []byte("p@ssw0rd")
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: createSRKRsp.ObjectHandle,
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

	// Create the blob
	// In a single session, authorize the use of the SRK (which has no auth value),
	//   encrypt the sealed data+auth with a session key, and
	//   encrypt a salt value with the SRK to derive the session key.
	t.Run("Create", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.Auth(createSRKRsp.Name.Buffer, nil),
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(srkHandle, srkPublic))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Load the sealed blob
	// The blob contents are protected by the TPM and don't need extra protection
	// by us, here.
	loadBlobCmd := tpm2.LoadCommand{
		ParentHandle: createSRKRsp.ObjectHandle,
		InPrivate:    createBlobRsp.OutPrivate,
		InPublic:     createBlobRsp.OutPublic,
	}
	var loadBlobRsp tpm2.LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp,
		tpm2.PasswordAuth(createSRKRsp.Name.Buffer, nil)); err != nil {
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

	// Unseal the blob
	// In a single session, authorize the use of the blob (with its low-entropy auth value),
	//   encrypt the unsealed data with a session key, and
	//   encrypt a salt value with the SRK to derive the session key.
	unsealCmd := tpm2.UnsealCommand{
		ItemHandle: loadBlobRsp.ObjectHandle,
	}
	var unsealRsp tpm2.UnsealResponse
	t.Run("WithAuth", func(t *testing.T) {
		if err := tpm.Execute(&unsealCmd, &unsealRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.Auth(loadBlobRsp.Name.Buffer, auth),
				tpm2.AESEncryption(128, tpm2.EncryptOut),
				tpm2.Salted(srkHandle, srkPublic))); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with an incorrect auth
	t.Run("WithWrongAuth", func(t *testing.T) {
		err := tpm.Execute(&unsealCmd, &unsealRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.Auth(loadBlobRsp.Name.Buffer, []byte("NotTheAuth")),
				tpm2.AESEncryption(128, tpm2.EncryptOut),
				tpm2.Salted(srkHandle, srkPublic)))
		if err == nil {
			t.Errorf("want TPM_RC_BAD_AUTH, got nil")
		}
		if !errors.Is(err, tpm2.TPMRCBadAuth) {
			t.Errorf("want TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 tpm2.Fmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})
}
