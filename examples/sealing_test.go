package tpmdirect_test

import (
	"testing"

	"github.com/chrisfenner/tpmdirect/reflect/tpmdirect"
	"github.com/chrisfenner/tpmdirect/tpm2"
)

// Test creating and flushing the SRK.
func TestCreateSRK(t *testing.T) {
	// TODO: connect to the TPM for testing.
	var tpm tpmdirect.TPM
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
