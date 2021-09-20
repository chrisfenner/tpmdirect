package sealing_test

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

	// Create the SRK
	createCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.NamedPrimaryHandle(tpm2.TPMRHOwner),
		InPublic:      tpm2.RSASRKTemplate,
	}
	var createRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createCmd, &createRsp, tpm2.PasswordSession(nil)); err != nil {
		t.Fatalf("%v", err)
	}
	srk = createRsp.ObjectHandle
	t.Logf("SRK handle: %x\n", createRsp.ObjectHandle)
	t.Logf("SRK name: %x\n", createRsp.Name)

	// Flush the SRK
	flushCmd := tpm2.FlushContextCommand{
		FlushHandle: srk,
	}
	var flushRsp tpm2.FlushContextResponse
	if err := tpm.Execute(&flushCmd, &flushRsp); err != nil {
		t.Fatalf("%v", err)
	}
}
