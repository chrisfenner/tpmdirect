package tpmdirect_test

import (
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating and flushing the SRK.
func TestCreateSRK(t *testing.T) {
	tpm, err := tpmdirect.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()
	var srk tpm2.TPMHandle
	t.Run("CreateSRK", func(t *testing.T) {
		cmd := tpm2.CreatePrimaryCommand{
			PrimaryHandle: tpm2.NamedPrimaryHandle(tpm2.TPMRHOwner),
			InPublic:      tpm2.RSASRKTemplate,
		}
		var rsp tpm2.CreatePrimaryResponse
		if err := tpm.Execute(&cmd, &rsp, tpm2.PasswordSession(nil)); err != nil {
			t.Fatalf("%v", err)
		}
		srk = rsp.ObjectHandle
		t.Logf("SRK handle: %x\n", rsp.ObjectHandle)
		t.Logf("SRK name: %x\n", rsp.Name)
	})
	t.Run("Flush", func(t *testing.T) {
		cmd := tpm2.FlushContextCommand{
			FlushHandle: srk,
		}
		var rsp tpm2.FlushContextResponse
		if err := tpm.Execute(&cmd, &rsp); err != nil {
			t.Fatalf("%v", err)
		}
	})
}
