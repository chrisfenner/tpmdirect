package tpm2_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating and unsealing a sealed data blob with a password and tpm2.HMAC.
func TestUnseal(t *testing.T) {
	templates := map[string]tpm2.TPM2BPublic{
		"RSA": tpm2.RSASRKTemplate,
		"ECC": tpm2.ECCSRKTemplate,
	}

	// Run the whole test for each of RSA and ECC SRKs.
	for name, srkTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			unsealingTest(t, srkTemplate)
		})
	}
}

func unsealingTest(t *testing.T, srkTemplate tpm2.TPM2BPublic) {
	tpm, err := tpm2.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to tpm2.TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the SRK
	// Put a password on the SRK to test more of the flows.
	srkAuth := []byte("mySRK")
	createSRKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: srkTemplate,
	}
	var createSRKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp); err != nil {
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
	// Include some trailing zeros to exercise the tpm2.TPM's trimming of them from auth values.
	auth := []byte("p@ssw0rd\x00\x00")
	auth2 := []byte("p@ssw0rd")
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: tpm2.AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   tpm2.PasswordAuth(srkAuth),
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
			},
		},
	}
	var createBlobRsp tpm2.CreateResponse

	// Create the blob with password auth, without any session encryption
	t.Run("Create", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob using an hmac auth session also for audit
	t.Run("CreateAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AuditExclusive())
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decryption
	t.Run("CreateDecrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AESEncryption(128, tpm2.EncryptIn))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for encryption
	t.Run("Createtpm2.Encrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AESEncryption(128, tpm2.EncryptOut))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decrypt and encrypt
	t.Run("CreateDecrypttpm2.Encrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AESEncryption(128, tpm2.EncryptInOut))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session
	t.Run("CreateDecrypttpm2.EncryptAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AESEncryption(128, tpm2.EncryptInOut),
				tpm2.Audit())
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session bound to SRK
	t.Run("CreateDecrypttpm2.Encrypttpm2.Salted", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth),
				tpm2.AESEncryption(128, tpm2.EncryptInOut),
				tpm2.Salted(createSRKRsp.ObjectHandle, createSRKRsp.OutPublic.PublicArea))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Use tpm2.HMAC auth to authorize the rest of the Create commands
	// Exercise re-using a use-once tpm2.HMAC structure (which will spin up the session each time)
	createBlobCmd.ParentHandle.Auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth))
	// Create the blob with a separate decrypt and encrypt session
	t.Run("CreateDecrypttpm2.EncryptSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for audit
	t.Run("CreateDecrypttpm2.EncryptAuditSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Audit())); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for exclusive audit
	t.Run("CreateDecrypttpm2.EncryptAuditExclusiveSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AuditExclusive())); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate decrypt and encrypt sessions.
	t.Run("CreateDecrypttpm2.Encrypt2Separate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			// Get weird with the algorithm and nonce choices. Mix lots of things together.
			tpm2.HMAC(tpm2.TPMAlgSHA1, 20, tpm2.AESEncryption(128, tpm2.EncryptIn)),
			tpm2.HMAC(tpm2.TPMAlgSHA384, 23, tpm2.AESEncryption(128, tpm2.EncryptOut))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate encrypt and decrypt sessions.
	// (The tpm2.TPM spec orders some extra nonces included in the first session in the order
	// noncetpm2.TPM_decrypt, noncetpm2.TPM_encrypt, so this exercises that)
	t.Run("CreateDecrypttpm2.Encrypt2Separate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			tpm2.HMAC(tpm2.TPMAlgSHA1, 17, tpm2.AESEncryption(128, tpm2.EncryptOut)),
			tpm2.HMAC(tpm2.TPMAlgSHA256, 32, tpm2.AESEncryption(128, tpm2.EncryptIn))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Load the sealed blob
	loadBlobCmd := tpm2.LoadCommand{
		ParentHandle: tpm2.AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(srkAuth)),
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic:  createBlobRsp.OutPublic,
	}
	var loadBlobRsp tpm2.LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp); err != nil {
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

	unsealCmd := tpm2.UnsealCommand{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}
	var unsealRsp tpm2.UnsealResponse
	// Unseal the blob with a password session
	t.Run("WithPassword", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = tpm2.PasswordAuth(auth)
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with an incorrect password session
	t.Run("WithWrongPassword", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = tpm2.PasswordAuth([]byte("NotThePassword"))
		err := tpm.Execute(&unsealCmd, &unsealRsp)
		if err == nil {
			t.Errorf("want tpm2.TPM_RC_BAD_AUTH, got nil")
		}
		if !errors.Is(err, tpm2.TPMRCBadAuth) {
			t.Errorf("want tpm2.TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 tpm2.Fmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want tpm2.TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})

	// Unseal the blob with a use-once tpm2.HMAC session
	t.Run("Withtpm2.HMAC", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth2))
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a use-once tpm2.HMAC session with encryption
	t.Run("Withtpm2.HMACtpm2.Encrypt", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth2),
			tpm2.AESEncryption(128, tpm2.EncryptOut))
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a standalone tpm2.HMAC session, re-using the session.
	t.Run("Withtpm2.HMACSession", func(t *testing.T) {
		sess, cleanup, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA1, 20, tpm2.Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle.Auth = sess

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})

	// Unseal the blob with a standalone bound tpm2.HMAC session, re-using the session.
	// Also, use session encryption.
	t.Run("Withtpm2.HMACSessiontpm2.Encrypt", func(t *testing.T) {
		sess, cleanup, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth2),
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle.Auth = sess

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})

	// Unseal the blob with a standalone tpm2.HMAC session, re-using the session.
	// Spin up another bound session for encryption.
	t.Run("Withtpm2.HMACSessiontpm2.EncryptSeparate", func(t *testing.T) {
		sess1, cleanup1, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA1, 16, tpm2.Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup1()
		sess2, cleanup2, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA384, 16,
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup2()
		unsealCmd.ItemHandle.Auth = sess1

		// It should be possible to use the sessions multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp, sess2); err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})
}
