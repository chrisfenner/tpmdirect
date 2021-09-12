package tpm2

const (
	CommandCodeCreate uint32 = 0x00000153
)

// Dummy interface for TPM command structures so that they can be
// easily distinguished from other types of structures.
type Command interface {
	// The TPM command code associated with this command.
	Command() TPMCC
}

// Dummy interface for TPM response structures so that they can be
// easily distinguished from other types of structures.
type Command interface {
	// The TPM command code associated with this command.
	Command() TPMCC
}

type Response interface {
	// The TPM command code associated with this response.
	Response() TPMCC
}

// Convenience type for handles preceded by @ in Part 3
type NamedHandle struct {
	Handle TPMHandle
	Name   []byte
}

// 12.1
type CreateCommand struct {
	// handle of parent for new object
	ParentHandle NamedHandle `tpm2:"auth=1"`
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

func (_ CreateCommand) Command() { return TPMCCCreate }

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

func (_ CreateResponse) Response() { return TPMCCCreate }

// 12.2
type LoadCommand struct {
	// handle of parent for new object
	ParentHandle NamedHandle `tpm2:"auth=1"`
	// the private portion of the object
	InPrivate TPM2BPrivate
	// the public portion of the object
	InPublic TPM2BPublic
}

func (_ LoadCommand) Command() { return TPMCCLoad }

type LoadResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle
	// Name of the loaded object
	Name TPM2BName
}

func (_ LoadResponse) Response() { return TPMCCLoad }

// 12.7
type UnsealCommand struct {
	ItemHandle NamedHandle `tpm2:"auth=1"`
}

func (_ UnsealCommand) Command() { return TPMCCUnseal }

type UnsealResponse struct {
	OutData TPM2BSensitiveData
}

func (_ UnsealResponse) Response() { return TPMCCUnseal }

// 24.1
type CreatePrimaryCommand struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle NamedHandle `tpm2:"auth=1"`
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

func (_ CreatePrimaryCommand) Command() { return TPMCCCreatePrimary }

type CreatePrimaryResponse struct {
	// handle of type TPM_HT_TRANSIENT for created Primary Object
	ObjectHandle TPMHandle
	// the public portion of the created object
	OutPublic TPM2BPublic
	// contains a TPMS_CREATION_DATA
	CreationData TPM2BCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket TPMTTKCreation
	// the name of the created object
	Name TPM2BName
}

func (_ CreatePrimaryResponse) Response() { return TPMCCCreatePrimary }

// 28.4
type FlushContextCommand struct {
	// the handle of the item to flush
	FlushHandle TPMIDHContext
}

func (_ FlushContextCommand) Command() { return TPMCCFlushContext }

type CreatePrimaryResponse struct {
}

func (_ FlushContextResponse) Response() { return TPMCCFlushContext }
