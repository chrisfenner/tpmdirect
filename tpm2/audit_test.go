package tpm2_test

import (
	"bytes"
	"testing"

	"github.com/chrisfenner/tpmdirect/tpm2"
)

func TestAuditSession(t *testing.T) {
	tpm, err := tpm2.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to tpm2.TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the audit session
	sess, cleanup, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanup()

	// Create the AK for audit
	createAKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
		},
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 true,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              false,
					SignEncrypt:          true,
				},
				Parameters: tpm2.TPMUPublicParms{
					ECCDetail: &tpm2.TPMSECCParms{
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.TPMUAsymScheme{
								ECDSA: &tpm2.TPMSSigSchemeECDSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							},
						},
						CurveID: tpm2.TPMECCNistP256,
					},
				},
			},
		},
	}
	var createAKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createAKCmd, &createAKRsp); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the AK
		flushCmd := tpm2.FlushContextCommand{
			FlushHandle: createAKRsp.ObjectHandle,
		}
		var flushRsp tpm2.FlushContextResponse
		if err := tpm.Execute(&flushCmd, &flushRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	audit := tpm2.NewAudit(tpm2.TPMAlgSHA256)
	// Call GetCapability a bunch of times with the audit session and make sure it extends like
	// we expect it to.
	props := []tpm2.TPMPT{
		tpm2.TPMPTFamilyIndicator,
		tpm2.TPMPTLevel,
		tpm2.TPMPTRevision,
		tpm2.TPMPTDayofYear,
		tpm2.TPMPTYear,
		tpm2.TPMPTManufacturer,
	}
	for _, prop := range props {
		getCmd := tpm2.GetCapabilityCommand{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}
		var getRsp tpm2.GetCapabilityResponse
		if err := tpm.Execute(&getCmd, &getRsp, sess); err != nil {
			t.Fatalf("%v", err)
		}
		if err := audit.Extend(&getCmd, &getRsp); err != nil {
			t.Fatalf("%v", err)
		}
		// Get the audit digest signed by the AK
		getAuditCmd := tpm2.GetSessionAuditDigestCommand{
			PrivacyAdminHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
			},
			SignHandle: tpm2.AuthHandle{
				Handle: createAKRsp.ObjectHandle,
			},
			SessionHandle:  sess.Handle(),
			QualifyingData: tpm2.TPM2BData{[]byte("foobar")},
		}
		var getAuditRsp tpm2.GetSessionAuditDigestResponse
		if err := tpm.Execute(&getAuditCmd, &getAuditRsp); err != nil {
			t.Errorf("%v", err)
		}
		// TODO check the signature with the AK pub
		aud := getAuditRsp.AuditInfo.AttestationData.Attested.SessionAudit
		if aud == nil {
			t.Fatalf("got nil session audit attestation")
		}
		want := audit.Digest()
		got := aud.SessionDigest.Buffer
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected audit value:\ngot %x\nwant %x", got, want)
		}
	}

}
