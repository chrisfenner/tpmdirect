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
// All implementations of this interface are pointers to
// structures, for settability.
// See https://go.dev/blog/laws-of-reflection
type Response interface {
	// The TPM command code associated with this response.
	Response() TPMCC
}

// Convenience type for handles preceded by @ in Part 3
type NamedHandle struct {
	Handle TPMHandle
	// Convenience value for auth calculation. Not serialized.
	Name []byte `tpmdirect:"skip"`
}

// 11.1
type StartAuthSessionCommand struct {
	// handle of a loaded decrypt key used to encrypt salt
	// may be TPM_RH_NULL
	TPMKey TPMIDHObject `tpmdirect:"handle"`
	// entity providing the authValue
	// may be TPM_RH_NULL
	Bind TPMIDHEntity `tpmdirect:"handle"`
	// initial nonceCaller, sets nonceTPM size for the session
	// shall be at least 16 octets
	NonceCaller TPM2BNonce
	// value encrypted according to the type of tpmKey
	// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
	EncryptedSalt TPM2BEncryptedSecret
	// indicates the type of the session; simple HMAC or policy (including a trial policy)
	SessionType TPMSE
	// the algorithm and key size for parameter encryption
	// may select TPM_ALG_NULL
	Symmetric TPMTSymDef
	// hash algorithm to use for the session
	// Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
	AuthHash TPMIAlgHash
}

func (_ *StartAuthSessionCommand) Command() TPMCC { return TPMCCStartAuthSession }

type StartAuthSessionResponse struct {
	// handle for the newly created session
	SessionHandle TPMISHAuthSession `tpmdirect:"handle"`
	// the initial nonce from the TPM, used in the computation of the sessionKey
	NonceTPM TPM2BNonce
}

func (_ *StartAuthSessionResponse) Response() TPMCC { return TPMCCStartAuthSession }

// 12.1
type CreateCommand struct {
	// handle of parent for new object
	ParentHandle NamedHandle `tpmdirect:"handle,auth"`
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

func (_ *CreateCommand) Command() TPMCC { return TPMCCCreate }

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

func (_ *CreateResponse) Response() TPMCC { return TPMCCCreate }

// 12.2
type LoadCommand struct {
	// handle of parent for new object
	ParentHandle NamedHandle `tpmdirect:"handle,auth"`
	// the private portion of the object
	InPrivate TPM2BPrivate
	// the public portion of the object
	InPublic TPM2BPublic
}

func (_ *LoadCommand) Command() TPMCC { return TPMCCLoad }

type LoadResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle `tpmdirect:"handle"`
	// Name of the loaded object
	Name TPM2BName
}

func (_ *LoadResponse) Response() TPMCC { return TPMCCLoad }

// 12.7
type UnsealCommand struct {
	ItemHandle NamedHandle `tpmdirect:"handle,auth"`
}

func (_ *UnsealCommand) Command() TPMCC { return TPMCCUnseal }

type UnsealResponse struct {
	OutData TPM2BSensitiveData
}

func (_ *UnsealResponse) Response() TPMCC { return TPMCCUnseal }

// 24.1
type CreatePrimaryCommand struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle NamedHandle `tpmdirect:"handle,auth"`
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

func (_ *CreatePrimaryCommand) Command() TPMCC { return TPMCCCreatePrimary }

type CreatePrimaryResponse struct {
	// handle of type TPM_HT_TRANSIENT for created Primary Object
	ObjectHandle TPMHandle `tpmdirect:"handle"`
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

func (_ *CreatePrimaryResponse) Response() TPMCC { return TPMCCCreatePrimary }

// 28.4
type FlushContextCommand struct {
	// the handle of the item to flush
	FlushHandle TPMIDHContext
}

func (_ *FlushContextCommand) Command() TPMCC { return TPMCCFlushContext }

type FlushContextResponse struct {
}

func (_ *FlushContextResponse) Response() TPMCC { return TPMCCFlushContext }
