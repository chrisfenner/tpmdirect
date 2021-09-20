package sealing_test

import (
	"bytes"
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating and unsealing a sealed data blob with a password.
func TestUnsealWithPassword(t *testing.T) {
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
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp, tpm2.PasswordSession(nil)); err != nil {
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
	createBlobCmd := tpm2.CreateCommand{
		ParentHandle: tpm2.NamedHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name: createSRKRsp.Name.Buffer,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate {
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte("p@ssw0rd"),
				},
				Data: tpm2.TPM2BData{
					Buffer: []byte("secrets"),
				},
			},
		},
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM: true,
					FixedParent: true,
					UserWithAuth: true,
					NoDA: true,
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
	if err := tpm.Execute(&createBlobCmd, &createBlobRsp, tpm2.PasswordSession(nil)); err != nil {
		t.Fatalf("%v", err)
	}

	// Load the sealed blob
	loadBlobCmd := tpm2.LoadCommand{
		ParentHandle: tpm2.NamedHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name: createSRKRsp.Name.Buffer,
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic: createBlobRsp.OutPublic,
	}
	var loadBlobRsp tpm2.LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp, tpm2.PasswordSession(nil)); err != nil {
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
		ItemHandle: tpm2.NamedHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name: loadBlobRsp.Name.Buffer,
		},
	}
	var unsealRsp tpm2.UnsealResponse
	if err := tpm.Execute(&unsealCmd, &unsealRsp, tpm2.PasswordSession([]byte("p@ssw0rd"))); err != nil {
		t.Errorf("%v", err)
	}
	want := []byte("secrets")
	if !bytes.Equal(unsealRsp.OutData.Buffer, want) {
		t.Errorf("want %x got %x", want, unsealRsp.OutData.Buffer)
	}
}
