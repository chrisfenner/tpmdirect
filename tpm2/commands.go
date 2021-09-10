package tpm2

const (
	CommandCodeCreate uint32 = 0x00000153
)

type CreateCommand struct {
	// handle of parent for new object
	ParentObject TPMIDHObject `tpm2:"auth=1"`
	// the sensitive data
	InSensitive TPM2BSensitiveCreate
	// the public template
	InPublic TPM2BPublic
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo TPM2BData
	// PCR that will be used in creation data
	CreationPCR TPMLPCRSelection
}

type CreateResponse struct {
	// the private portion of the object
	OutPrivate TPM2BPrivate
	// the public portion of the created object
	OutPublic TPM2BPublic
	// contains a TPMS_CREATION_DATA
	CreationData TPM2BCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket TPMTTKCreation
}
