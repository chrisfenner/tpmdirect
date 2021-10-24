package tpm2

import "fmt"

// Part 1 structures that aren't defined in Part 2
type TPMCmdHeader struct {
	Tag         TPMISTCommandTag
	Length      uint32
	CommandCode TPMCC
}

type TPMRspHeader struct {
	Tag          TPMISTCommandTag
	Length       uint32
	ResponseCode TPMRC
}

// 5.3

// this is the 1.2 compatible form of the TPM_ALG_ID
type TPMAlgorithmID uint32

type TPMModifierIndicator uint32

// the authorizationSize parameter in a command
type TPMAuthorizationSize uint32

// the parameterSize parameter in a command
type TPMParameterSize uint32

// a key size in octets
type TPMKeySize uint16

// a key size in bits
type TPMKeyBits uint16

// 6.2
type TPMGenerated uint32

func (g TPMGenerated) Check() error {
	if g != TPMGeneratedValue {
		return fmt.Errorf("TPM_GENERATED value should be 0x%x, was 0x%x", TPMGeneratedValue, g)
	}
	return nil
}

// 6.3
type TPMAlgID uint16

// 6.4
type TPMECCCurve uint16

// 6.5.2
type TPMCC uint32

// 6.6
type TPMRC uint32

// 6.9
type TPMST uint16

// 6.11
type TPMSE uint8

// 6.12
type TPMCap uint32

// 6.13
type TPMPT uint32

// 6.14
type TPMPTPCR uint32

// 7.1
type TPMHandle uint32

// 8.2
type TPMAAlgorithm struct {
	// SET (1): an asymmetric algorithm with public and private portions
	// CLEAR (0): not an asymmetric algorithm
	Asymmetric bool `tpmdirect:"bit=0"`
	// SET (1): a symmetric block cipher
	// CLEAR (0): not a symmetric block cipher
	Symmetric bool `tpmdirect:"bit=1"`
	// SET (1): a hash algorithm
	// CLEAR (0): not a hash algorithm
	Hash bool `tpmdirect:"bit=2"`
	// SET (1): an algorithm that may be used as an object type
	// CLEAR (0): an algorithm that is not used as an object type
	Object    bool  `tpmdirect:"bit=3"`
	Reserved1 uint8 `tpmdirect:"bit=7:4"`
	// SET (1): a signing algorithm. The setting of asymmetric,
	// symmetric, and hash will indicate the type of signing algorithm.
	// CLEAR (0): not a signing algorithm
	Signing bool `tpmdirect:"bit=8"`
	// SET (1): an encryption/decryption algorithm. The setting of
	// asymmetric, symmetric, and hash will indicate the type of
	// encryption/decryption algorithm.
	// CLEAR (0): not an encryption/decryption algorithm
	Encrypting bool `tpmdirect:"bit=9"`
	// SET (1): a method such as a key derivative function (KDF)
	// CLEAR (0): not a method
	Method    bool   `tpmdirect:"bit=10"`
	Reserved2 uint32 `tpmdirect:"bit=31:11"`
}

// 8.3.2
type TPMAObject struct {
	// shall be zero
	Reserved1 uint8 `tpmdirect:"bit=0"`
	// SET (1): The hierarchy of the object, as indicated by its
	// Qualified Name, may not change.
	// CLEAR (0): The hierarchy of the object may change as a result
	// of this object or an ancestor key being duplicated for use in
	// another hierarchy.
	FixedTPM bool `tpmdirect:"bit=1"`
	// SET (1): Previously saved contexts of this object may not be
	// loaded after Startup(CLEAR).
	// CLEAR (0): Saved contexts of this object may be used after a
	// Shutdown(STATE) and subsequent Startup().
	STClear bool `tpmdirect:"bit=2"`
	// shall be zero
	Reserved2 uint8 `tpmdirect:"bit=3"`
	// SET (1): The parent of the object may not change.
	// CLEAR (0): The parent of the object may change as the result of
	// a TPM2_Duplicate() of the object.
	FixedParent bool `tpmdirect:"bit=4"`
	// SET (1): Indicates that, when the object was created with
	// TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of
	// the sensitive data other than the authValue.
	// CLEAR (0): A portion of the sensitive data, other than the
	// authValue, was provided by the caller.
	SensitiveDataOrigin bool `tpmdirect:"bit=5"`
	// SET (1): Approval of USER role actions with this object may be
	// with an HMAC session or with a password using the authValue of
	// the object or a policy session.
	// CLEAR (0): Approval of USER role actions with this object may
	// only be done with a policy session.
	UserWithAuth bool `tpmdirect:"bit=6"`
	// SET (1): Approval of ADMIN role actions with this object may
	// only be done with a policy session.
	// CLEAR (0): Approval of ADMIN role actions with this object may
	// be with an HMAC session or with a password using the authValue
	// of the object or a policy session.
	AdminWithPolicy bool `tpmdirect:"bit=7"`
	// shall be zero
	Reserved3 uint8 `tpmdirect:"bit=9:8"`
	// SET (1): The object is not subject to dictionary attack
	// protections.
	// CLEAR (0): The object is subject to dictionary attack
	// protections.
	NoDA bool `tpmdirect:"bit=10"`
	// SET (1): If the object is duplicated, then symmetricAlg shall
	// not be TPM_ALG_NULL and newParentHandle shall not be
	// TPM_RH_NULL.
	// CLEAR (0): The object may be duplicated without an inner
	// wrapper on the private portion of the object and the new parent
	// may be TPM_RH_NULL.
	EncryptedDuplication bool `tpmdirect:"bit=11"`
	// shall be zero
	Reserved4 uint8 `tpmdirect:"bit=15:12"`
	// SET (1): Key usage is restricted to manipulate structures of
	// known format; the parent of this key shall have restricted SET.
	// CLEAR (0): Key usage is not restricted to use on special
	// formats.
	Restricted bool `tpmdirect:"bit=16"`
	// SET (1): The private portion of the key may be used to decrypt.
	// CLEAR (0): The private portion of the key may not be used to
	// decrypt.
	Decrypt bool `tpmdirect:"bit=17"`
	// SET (1): For a symmetric cipher object, the private portion of
	// the key may be used to encrypt. For other objects, the private
	// portion of the key may be used to sign.
	// CLEAR (0): The private portion of the key may not be used to
	// sign or encrypt.
	SignEncrypt bool `tpmdirect:"bit=18"`
	// SET (1): An asymmetric key that may not be used to sign with
	// TPM2_Sign() CLEAR (0): A key that may be used with TPM2_Sign()
	// if sign is SET
	// NOTE: This attribute only has significance if sign is SET.
	X509Sign bool `tpmdirect:"bit=19"`
	// shall be zero
	Reserved5 uint16 `tpmdirect:"bit=31:20"`
}

// 8.4
type TPMASession struct {
	// SET (1): In a command, this setting indicates that the session
	// is to remain active after successful completion of the command.
	// In a response, it indicates that the session is still active.
	// If SET in the command, this attribute shall be SET in the response.
	// CLEAR (0): In a command, this setting indicates that the TPM should
	// close the session and flush any related context when the command
	// completes successfully. In a response, it indicates that the
	// session is closed and the context is no longer active.
	// This attribute has no meaning for a password authorization and the
	// TPM will allow any setting of the attribute in the command and SET
	// the attribute in the response.
	ContinueSession bool `tpmdirect:"bit=0"`
	// SET (1): In a command, this setting indicates that the command
	// should only be executed if the session is exclusive at the start of
	// the command. In a response, it indicates that the session is
	// exclusive. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the session need not be
	// exclusive at the start of the command. In a response, indicates that
	// the session is not exclusive.
	AuditExclusive bool `tpmdirect:"bit=1"`
	// SET (1): In a command, this setting indicates that the audit digest
	// of the session should be initialized and the exclusive status of the
	// session SET. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the audit digest should not
	// be initialized. This bit is always CLEAR in a response.
	AuditReset bool `tpmdirect:"bit=2"`
	// shall be CLEAR
	Reserved1 bool `tpmdirect:"bit=3"`
	// shall be CLEAR
	Reserved2 bool `tpmdirect:"bit=4"`
	// SET (1): In a command, this setting indicates that the first
	// parameter in the command is symmetrically encrypted using the
	// parameter encryption scheme described in TPM 2.0 Part 1. The TPM will
	// decrypt the parameter after performing any HMAC computations and
	// before unmarshaling the parameter. In a response, the attribute is
	// copied from the request but has no effect on the response.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Decrypt bool `tpmdirect:"bit=5"`
	// SET (1): In a command, this setting indicates that the TPM should use
	// this session to encrypt the first parameter in the response. In a
	// response, it indicates that the attribute was set in the command and
	// that the TPM used the session to encrypt the first parameter in the
	// response using the parameter encryption scheme described in TPM 2.0
	// Part 1.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Encrypt bool `tpmdirect:"bit=6"`
	// SET (1): In a command or response, this setting indicates that the
	// session is for audit and that auditExclusive and auditReset have
	// meaning. This session may also be used for authorization, encryption,
	// or decryption. The encrypted and encrypt fields may be SET or CLEAR.
	// CLEAR (0): Session is not used for audit.
	// If SET in the command, then this attribute will be SET in the response.
	Audit bool `tpmdirect:"bit=7"`
}

// 8.5
type TPMALocality struct {
	TPMLocZero  bool `tpmdirect:"bit=0"`
	TPMLocOne   bool `tpmdirect:"bit=1"`
	TPMLocTwo   bool `tpmdirect:"bit=2"`
	TPMLocThree bool `tpmdirect:"bit=3"`
	TPMLocFour  bool `tpmdirect:"bit=4"`
	// If any of these bits is set, an extended locality is indicated
	Extended uint8 `tpmdirect:"bit=7:5"`
}

// 8.9
type TPMACC struct {
	// indicates the command being selected
	CommandIndex uint16 `tpmdirect:"bit=15:0"`
	// shall be zero
	Reserved1 uint16 `tpmdirect:"bit=21:16"`
	// SET (1): indicates that the command may write to NV
	// CLEAR (0): indicates that the command does not write to NV
	NV bool `tpmdirect:"bit=22"`
	// SET (1): This command could flush any number of loaded contexts.
	// CLEAR (0): no additional changes other than indicated by the flushed attribute
	Extensive bool `tpmdirect:"bit=23"`
	// SET (1): The context associated with any transient handle in the command will be flushed when this command completes.
	// CLEAR (0): No context is flushed as a side effect of this command.
	Flushed bool `tpmdirect="bit=24"`
	// indicates the number of the handles in the handle area for this command
	CHandles uint8 `tpmdirect="bit=27:25"`
	// SET (1): indicates the presence of the handle area in the response
	RHandle bool `tpmdirect="bit=28"`
	// SET (1): indicates that the command is vendor-specific
	// CLEAR (0): indicates that the command is defined in a version of this specification
	V bool `tpmdirect="bit=29"`
	// allocated for software; shall be zero
	Reserved2 uint8 `tpmdirect:"bit=31:30"`
}

// 8.12
type TPMAACT struct {
	// SET (1): The ACT has signaled
	// CLEAR (0): The ACT has not signaled
	Signaled bool `tpmdirect:"bit=0"`
	// SET (1): The ACT signaled bit is preserved over a power cycle
	// CLEAR (0): The ACT signaled bit is not preserved over a power cycle
	PreserveSignaled bool `tpmdirect:"bit=1"`
	// shall be zero
	Reserved uint32 `tpmdirect:"bit=31:2"`
}

// 9.2
// Use native bool for TPMI_YES_NO; encoding/binary already treats this as 8 bits wide.
type TPMIYesNo = bool

// 9.3
type TPMIDHObject = TPMHandle

// 9.6
type TPMIDHEntity = TPMHandle

// 9.8
type TPMISHAuthSession = TPMHandle

// 9.9
type TPMISHHMAC = TPMHandle

// 9.10
type TPMISHPolicy = TPMHandle

// 9.11
type TPMIDHContext = TPMHandle

// 9.13
type TPMIRHHierarchy = TPMHandle

// 9.27
type TPMIAlgHash = TPMAlgID

// TODO: Provide a dummy interface here so we can explicitly enumerate them
// for compile-time protection.

// 9.29
type TPMIAlgSym = TPMAlgID

// 9.30
type TPMIAlgSymObject = TPMAlgID

// 9.31
type TPMIAlgSymMode = TPMAlgID

// 9.32
type TPMIAlgKDF = TPMAlgID

// 9.33
type TPMIAlgSigScheme = TPMAlgID

// 9.35
type TPMISTCommandTag = TPMST

// 10.1
type TPMSEmpty = struct{}

// 10.3.1
type TPMUHA struct {
	SHA1     *[20]byte `tpmdirect:"selector=0x0004"` // TPM_ALG_SHA1
	SHA256   *[32]byte `tpmdirect:"selector=0x000B"` // TPM_ALG_SHA256
	SHA384   *[48]byte `tpmdirect:"selector=0x000C"` // TPM_ALG_SHA384
	SHA512   *[64]byte `tpmdirect:"selector=0x000D"` // TPM_ALG_SHA512
	SHA3_256 *[32]byte `tpmdirect:"selector=0x0027"` // TPM_ALG_SHA3_256
	SHA3_384 *[48]byte `tpmdirect:"selector=0x0028"` // TPM_ALG_SHA3_384
	SHA3_512 *[64]byte `tpmdirect:"selector=0x0029"` // TPM_ALG_SHA3_512
}

// 10.3.2
type TPMTHA struct {
	// selector of the hash contained in the digest that implies the size of the digest
	HashAlg TPMIAlgHash `tpmdirect:"nullable"`
	// the digest data
	Digest TPMUHA `tpmdirect:"tag=HashAlg"`
}

// 10.4.2
type TPM2BDigest TPM2BData

// 10.4.3
type TPM2BData struct {
	// size in octets of the buffer field; may be 0
	Buffer []byte `tpmdirect:"sized"`
}

// 10.4.4
type TPM2BNonce TPM2BDigest

// 10.4.7
type TPM2BEvent TPM2BData

// 10.4.10
type TPM2BTimeout TPM2BData

// 10.4.5
type TPM2BAuth TPM2BDigest

// 10.5.3
// NOTE: This structure does not contain a TPMUName, because that union
// is not tagged with a selector. Instead, TPM2B_Name is flattened and
// all TPMDirect helpers that deal with names will deal with them as so.
type TPM2BName TPM2BData

// 10.6.2
type TPMSPCRSelection struct {
	Hash      TPMIAlgHash
	PCRSelect []byte `tpmdirect:"sized8"`
}

// 10.7.3
type TPMTTKCreation struct {
	// ticket structure tag
	Tag TPMST
	// the hierarchy containing name
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// 10.7.5
type TPMTTKAuth struct {
	// ticket structure tag
	Tag TPMST
	// the hierarchy of the object used to produce the ticket
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// 10.8.1
type TPMSAlgProperty struct {
	// an algorithm identifier
	Alg TPMAlgID
	// the attributes of the algorithm
	AlgProperties TPMAAlgorithm
}

// 10.8.2
type TPMSTaggedProperty struct {
	// a property identifier
	Property TPMPT
	// the value of the property
	Value uint32
}

// 10.8.3
type TPMSTaggedPCRSelect struct {
	// the property identifier
	Tag TPMPTPCR
	// the bit map of PCR with the identified property
	PCRSelect []byte `tpmdirect:"sized8"`
}

// 10.8.4
type TPMSTaggedPolicy struct {
	// a permanent handle
	Handle TPMHandle
	// the policy algorithm and hash
	PolicyHash TPMTHA
}

// 10.8.5
type TPMSACTData struct {
	// a permanent handle
	Handle TPMHandle
	// the current timeout of the ACT
	Timeout uint32
	// the state of the ACT
	Attributes TPMAACT
}

// 10.9.1
type TPMLCC struct {
	CommandCodes []TPMCC `tpmdirect:"list"`
}

// 10.9.2
type TPMLCCA struct {
	CommandAttributes []TPMACC `tpmdirect:"list"`
}

// 10.9.3
type TPMLAlg struct {
	Algorithms []TPMAlgID `tpmdirect:"list"`
}

// 10.9.4
type TPMLHandle struct {
	Handle []TPMHandle `tpmdirect:"list"`
}

// 10.9.5
type TPMLDigest struct {
	// a list of digests
	Digests []TPM2BDigest `tpmdirect:"list"`
}

// 10.9.6
type TPMLDigestValues struct {
	// a list of tagged digests
	Digests []TPMTHA `tpmdirect:"list"`
}

// 10.9.7
type TPMLPCRSelection struct {
	PCRSelections []TPMSPCRSelection `tpmdirect:"list"`
}

// 10.9.8
type TPMLAlgProperty struct {
	AlgProperties []TPMSAlgProperty `tpmdirect:"list"`
}

// 10.9.9
type TPMLTaggedTPMProperty struct {
	TPMProperty []TPMSTaggedProperty `tpmdirect:"list"`
}

// 10.9.10
type TPMLTaggedPCRProperty struct {
	PCRProperty []TPMSTaggedPCRSelect `tpmdirect:"list"`
}

// 10.9.11
type TPMLECCCurve struct {
	ECCCurves []TPMECCCurve `tpmdirect:"list"`
}

// 10.9.12
type TPMLTaggedPolicy struct {
	Policies []TPMSTaggedPolicy `tpmdirect:"list"`
}

// 10.9.13
type TPMLACTData struct {
	ACTData []TPMSACTData `tpmdirect:"list"`
}

// 10.10.1
type TPMUCapabilities struct {
	Algorithms    *TPMLAlgProperty       `tpmdirect:"selector=0x00000000"` // TPM_CAP_ALGS
	Handles       *TPMLHandle            `tpmdirect:"selector=0x00000001"` // TPM_CAP_HANDLES
	Command       *TPMLCCA               `tpmdirect:"selector=0x00000002"` // TPM_CAP_COMMANDS
	PPCommands    *TPMLCC                `tpmdirect:"selector=0x00000003"` // TPM_CAP_PP_COMMANDS
	AuditCommands *TPMLCC                `tpmdirect:"selector=0x00000004"` // TPM_CAP_AUDIT_COMMANDS
	AssignedPCR   *TPMLPCRSelection      `tpmdirect:"selector=0x00000005"` // TPM_CAP_PCRS
	TPMProperties *TPMLTaggedTPMProperty `tpmdirect:"selector=0x00000006"` // TPM_CAP_TPM_PROPERTIES
	PCRProperties *TPMLTaggedPCRProperty `tpmdirect:"selector=0x00000007"` // TPM_CAP_PCR_PROPERTIES
	ECCCurves     *TPMLECCCurve          `tpmdirect:"selector=0x00000008"` // TPM_CAP_ECC_CURVES
	AuthPolicies  *TPMLTaggedPolicy      `tpmdirect:"selector=0x00000009"` // TPM_CAP_AUTH_POLICIES
	ACTData       *TPMLACTData           `tpmdirect:"selector=0x0000000A"` // TPM_CAP_ACT
}

// 10.10.2
type TPMSCapabilityData struct {
	// the capability
	Capability TPMCap
	// the capability data
	Data TPMUCapabilities `tpmdirect:"tag=Capability"`
}

// 10.11.1
type TPMSClockInfo struct {
	// time value in milliseconds that advances while the TPM is powered
	Clock uint64
	// number of occurrences of TPM Reset since the last TPM2_Clear()
	ResetCount uint32
	// number of times that TPM2_Shutdown() or _TPM_Hash_Start have
	// occurred since the last TPM Reset or TPM2_Clear().
	RestartCount uint32
	// no value of Clock greater than the current value of Clock has been
	// previously reported by the TPM. Set to YES on TPM2_Clear().
	Safe TPMIYesNo
}

// 10.11.6
type TPMSTimeInfo struct {
	// time in milliseconds since the TIme circuit was last reset
	Time uint64
	// a structure containing the clock information
	ClockInfo TPMSClockInfo
}

// 10.12.2
type TPMSTimeAttestInfo struct {
	// the Time, Clock, resetCount, restartCount, and Safe indicator
	Time TPMSTimeInfo
	// a TPM vendor-specific value indicating the version number of the firmware
	FirmwareVersion uint64
}

// 10.12.3
type TPMSCertifyInfo struct {
	// Name of the certified object
	Name TPM2BName
	// Qualified Name of the certified object
	QualifiedName TPM2BName
}

// 10.12.4
type TPMSQuoteInfo struct {
	// information on algID, PCR selected and digest
	PCRSelect TPMLPCRSelection
	// digest of the selected PCR using the hash of the signing key
	PCRDigest TPM2BDigest
}

// 10.12.5
type TPMSCommandAuditInfo struct {
	// the monotonic audit counter
	AuditCounter uint64
	// hash algorithm used for the command audit
	DigestAlg TPMAlgID
	// the current value of the audit digest
	AuditDigest TPM2BDigest
	// digest of the command codes being audited using digestAlg
	CommandDigest TPM2BDigest
}

// 10.12.6
type TPMSSessionAuditInfo struct {
	// current exclusive status of the session
	ExclusiveSession TPMIYesNo
	// the current value of the session audit digest
	SessionDigest TPM2BDigest
}

// 10.12.7
type TPMSCreationInfo struct {
	// Name of the object
	ObjectName TPM2BName
	// creationHash
	CreationHash TPM2BDigest
}

// 10.12.8
type TPMSNVCertifyInfo struct {
	// Name of the NV Index
	IndexName TPM2BName
	// the offset parameter of TPM2_NV_Certify()
	Offset uint16
	// contents of the NV Index
	NVContents TPM2BData
}

// 10.12.9
type TPMSNVDigestCertifyInfo struct {
	// Name of the NV Index
	IndexName TPM2BName
	// hash of the contents of the index
	NVDigest TPM2BDigest
}

// 10.12.10
type TPMISTAttest = TPMST

// 10.12.11
type TPMUAttest struct {
	NV           *TPMSNVCertifyInfo       `tpmdirect:"selector=0x8014"` // TPM_ST_ATTEST_NV
	CommandAudit *TPMSCommandAuditInfo    `tpmdirect:"selector=0x8015"` // TPM_ST_ATTEST_COMMAND_AUDIT
	SessionAudit *TPMSSessionAuditInfo    `tpmdirect:"selector=0x8016"` // TPM_ST_ATTEST_SESSION_AUDIT
	Certify      *TPMSCertifyInfo         `tpmdirect:"selector=0x8017"` // TPM_ST_ATTEST_CERTIFY
	Quote        *TPMSQuoteInfo           `tpmdirect:"selector=0x8018"` // TPM_ST_ATTEST_QUOTE
	Time         *TPMSTimeAttestInfo      `tpmdirect:"selector=0x8019"` // TPM_ST_ATTEST_TIME
	Creation     *TPMSCreationInfo        `tpmdirect:"selector=0x801A"` // TPM_ST_ATTEST_CREATION
	NVDigest     *TPMSNVDigestCertifyInfo `tpmdirect:"selector=0x801C"` // TPM_ST_ATTEST_NV_DIGEST
}

// 10.12.12
type TPMSAttest struct {
	// the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
	Magic TPMGenerated `tpmdirect:"check"`
	// type of the attestation structure
	Type TPMISTAttest
	// Qualified Name of the signing key
	QualifiedSigner TPM2BName
	// external information supplied by caller
	ExtraData TPM2BData
	// Clock, resetCount, restartCount, and Safe
	ClockInfo TPMSClockInfo
	// TPM-vendor-specific value identifying the version number of the firmware
	FirmwareVersion uint64
	// the type-specific attestation information
	Attested TPMUAttest `tpmdirect:"tag=Type"`
}

// 10.12.13
// Note that in the spec, this is just a 2B_DATA with enough room for an S_ATTEST.
// For ergonomics, pretend that TPM2B_Attest wraps a TPMS_Attest just like other 2Bs.
type TPM2BAttest struct {
	// the signed structure
	AttestationData TPMSAttest `tpmdirect:"sized"`
}

// 10.13.2
type TPMSAuthCommand struct {
	Handle        TPMISHAuthSession
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

// 10.13.3
type TPMSAuthResponse struct {
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

// 11.1.3
type TPMUSymKeyBits struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMKeyBits  `tpmdirect:"selector=0x0006"` // TPM_ALG_AES
	XOR *TPMIAlgHash `tpmdirect:"selector=0x000A"` // TPM_ALG_XOR
}

// 11.1.4
type TPMUSymMode struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMIAlgSymMode `tpmdirect:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{}       `tpmdirect:"selector=0x000A"` // TPM_ALG_XOR
}

// 11.1.5
type TPMUSymDetails struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *struct{} `tpmdirect:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{} `tpmdirect:"selector=0x000A"` // TPM_ALG_XOR
}

// 11.1.6
type TPMTSymDef struct {
	// indicates a symmetric algorithm
	Algorithm TPMIAlgSym `tpmdirect:"nullable"`
	// the key size
	KeyBits TPMUSymKeyBits `tpmdirect:"tag=Algorithm"`
	// the mode for the key
	Mode TPMUSymMode `tpmdirect:"tag=Algorithm"`
	// contains the additional algorithm details
	Details TPMUSymDetails `tpmdirect:"tag=Algorithm"`
}

// 11.1.7
type TPMTSymDefObject struct {
	// selects a symmetric block cipher
	// When used in the parameter area of a parent object, this shall
	// be a supported block cipher and not TPM_ALG_NULL
	Algorithm TPMIAlgSymObject `tpmdirect:"nullable"`
	// the key size
	KeyBits TPMUSymKeyBits `tpmdirect:"tag=Algorithm"`
	// default mode
	// When used in the parameter area of a parent object, this shall
	// be TPM_ALG_CFB.
	Mode TPMUSymMode `tpmdirect:"tag=Algorithm"`
	// contains the additional algorithm details, if any
	Details TPMUSymDetails `tpmdirect:"tag=Algorithm"`
}

// 11.1.9
type TPMSSymCipherParms struct {
	// a symmetric block cipher
	Sym TPMTSymDefObject
}

// 11.1.14
type TPM2BSensitiveData TPM2BData

// 11.1.15
type TPMSSensitiveCreate struct {
	// the USER auth secret value.
	UserAuth TPM2BAuth
	// data to be sealed, a key, or derivation values.
	Data TPM2BData
}

// 11.1.16
type TPM2BSensitiveCreate struct {
	// data to be sealed or a symmetric key value.
	Sensitive TPMSSensitiveCreate `tpmdirect:"sized"`
}

// 11.1.17
type TPMSSchemeHash struct {
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
}

// 11.1.10
type TPMIAlgKeyedHashScheme = TPMAlgID

// 11.1.20
type TPMSSchemeHMAC TPMSSchemeHash

// 11.1.21
type TPMSSchemeXOR struct {
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
	// the key derivation function
	KDF TPMIAlgKDF
}

// 11.1.22
type TPMUSchemeKeyedHash struct {
	HMAC *TPMSSchemeHMAC `tpmdirect:"selector=0x0005"` // TPM_ALG_HMAC
	XOR  *TPMSSchemeXOR  `tpmdirect:"selector=0x000A"` // TPM_ALG_XOR
}

// 11.1.23
type TPMTKeyedHashScheme struct {
	Scheme  TPMIAlgKeyedHashScheme `tpmdirect:"nullable"`
	Details TPMUSchemeKeyedHash    `tpmdirect:"tag=Scheme"`
}

// 11.2.1.2
type TPMSSigSchemeRSASSA TPMSSchemeHash
type TPMSSigSchemeRSAPSS TPMSSchemeHash

// 11.2.1.3
type TPMSSigSchemeECDSA TPMSSchemeHash

// 11.2.1.4
type TPMUSigScheme struct {
	HMAC   *TPMSSchemeHMAC `tpmdirect:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *TPMSSchemeHash `tpmdirect:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *TPMSSchemeHash `tpmdirect:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *TPMSSchemeHash `tpmdirect:"selector=0x0018"` // TPM_ALG_ECDSA
}

// 11.2.1.5
type TPMTSigScheme struct {
	Scheme  TPMIAlgSigScheme `tpmdirect:"nullable"`
	Details TPMUSigScheme    `tpmdirect:"tag=Scheme"`
}

// 11.2.2.2
type TPMSEncSchemeRSAES TPMSEmpty
type TPMSEncSchemeOAEP TPMSSchemeHash

// 11.2.2.3
type TPMSKeySchemeECDH TPMSSchemeHash

// 11.2.3.1
type TPMSKDFSchemeMGF1 TPMSSchemeHash
type TPMSKDFSchemeECDH TPMSSchemeHash
type TPMSKDFSchemeKDF1SP80056A TPMSSchemeHash
type TPMSKDFSchemeKDF2 TPMSSchemeHash
type TPMSKDFSchemeKDF1SP800108 TPMSSchemeHash

// 11.2.3.2
type TPMUKDFScheme struct {
	MGF1         *TPMSKDFSchemeMGF1         `tpmdirect:"selector=0x0007"` // TPM_ALG_MGF1
	ECDH         *TPMSKDFSchemeECDH         `tpmdirect:"selector=0x0019"` // TPM_ALG_ECDH
	KDF1SP80056A *TPMSKDFSchemeKDF1SP80056A `tpmdirect:"selector=0x0020"` // TPM_ALG_KDF1_SP800_56A
	KDF2         *TPMSKDFSchemeKDF2         `tpmdirect:"selector=0x0021"` // TPM_ALG_KDF2
	KDF1SP800108 *TPMSKDFSchemeKDF1SP800108 `tpmdirect:"selector=0x0022"` // TPM_ALG_KDF1_SP800_108
}

// 11.2.3.3
type TPMTKDFScheme struct {
	// scheme selector
	Scheme TPMIAlgKDF `tpmdirect:"nullable"`
	// scheme parameters
	Details TPMUKDFScheme `tpmdirect:"tag=Scheme"`
}

// 11.2.3.5
type TPMUAsymScheme struct {
	// TODO every asym scheme gets an entry in this union.
	RSASSA *TPMSSigSchemeRSASSA `tpmdirect:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAES  *TPMSEncSchemeRSAES  `tpmdirect:"selector=0x0015"` // TPM_ALG_RSAES
	RSAPSS *TPMSSigSchemeRSAPSS `tpmdirect:"selector=0x0016"` // TPM_ALG_RSAPSS
	OAEP   *TPMSEncSchemeOAEP   `tpmdirect:"selector=0x0017"` // TPM_ALG_OAEP
	ECDSA  *TPMSSigSchemeECDSA  `tpmdirect:"selector=0x0018"` // TPM_ALG_ECDSA
	ECDH   *TPMSKeySchemeECDH   `tpmdirect:"selector=0x0019"` // TPM_ALG_ECDH
}

// 11.2.4.1
type TPMIAlgRSAScheme = TPMAlgID

// 11.2.4.2
type TPMTRSAScheme struct {
	// scheme selector
	Scheme TPMIAlgRSAScheme `tpmdirect:"nullable"`
	// scheme parameters
	Details TPMUAsymScheme `tpmdirect:"tag=Scheme"`
}

// 11.2.4.5
type TPM2BPublicKeyRSA TPM2BData

// 11.2.4.6
type TPMIRSAKeyBits = TPMKeyBits

// 11.2.5.1
type TPM2BECCParameter TPM2BData

// 11.2.5.2
type TPMSECCPoint struct {
	// X coordinate
	X TPM2BECCParameter
	// Y coordinate
	Y TPM2BECCParameter
}

// 11.2.5.4
type TPMIAlgECCScheme = TPMAlgID

// 11.2.5.5
type TPMIECCCurve = TPMECCCurve

// 11.2.5.6
type TPMTECCScheme struct {
	// scheme selector
	Scheme TPMIAlgECCScheme `tpmdirect:"nullable"`
	// scheme parameters
	Details TPMUAsymScheme `tpmdirect:"tag=Scheme"`
}

// 11.3.1
type TPMSSignatureRSA struct {
	// the hash algorithm used to digest the message
	Hash TPMIAlgHash
	// The signature is the size of a public key.
	Sig TPM2BPublicKeyRSA
}

// 11.3.2
type TPMSSignatureECC struct {
	// the hash algorithm used in the signature process
	Hash       TPMIAlgHash
	SignatureR TPM2BECCParameter
	SignatureS TPM2BECCParameter
}

// 11.3.3
type TPMUSignature struct {
	HMAC   *TPMTHA           `tpmdirect:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *TPMSSignatureRSA `tpmdirect:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *TPMSSignatureRSA `tpmdirect:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *TPMSSignatureECC `tpmdirect:"selector=0x0018"` // TPM_ALG_ECDSA
}

// 11.3.4
type TPMTSignature struct {
	// selector of the algorithm used to construct the signature
	SigAlg TPMIAlgSigScheme `tpmdirect:"nullable"`
	// This shall be the actual signature information.
	Signature TPMUSignature `tpmdirect:"tag=SigAlg"`
}

// 11.4.33
type TPM2BEncryptedSecret TPM2BData

// 12.2.2
type TPMIAlgPublic = TPMAlgID

// 12.2.3.2
type TPMUPublicID struct {
	KeyedHash *TPM2BDigest       `tpmdirect:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	Sym       *TPM2BDigest       `tpmdirect:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	RSA       *TPM2BPublicKeyRSA `tpmdirect:"selector=0x0001"` // TPM_ALG_RSA
	ECC       *TPMSECCPoint      `tpmdirect:"selector=0x0023"` // TPM_ALG_ECC
}

// 12.2.3.3
type TPMSKeyedHashParms struct {
	// Indicates the signing method used for a keyedHash signing
	// object. This field also determines the size of the data field
	// for a data object created with TPM2_Create() or
	// TPM2_CreatePrimary().
	Scheme TPMTKeyedHashScheme
}

// 12.2.3.5
type TPMSRSAParms struct {
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size, and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric TPMTSymDefObject
	// scheme.scheme shall be:
	// for an unrestricted signing key, either TPM_ALG_RSAPSS
	// TPM_ALG_RSASSA or TPM_ALG_NULL
	// for a restricted signing key, either TPM_ALG_RSAPSS or
	// TPM_ALG_RSASSA
	// for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP,
	// or TPM_ALG_NULL unless the object also has the sign attribute
	// for a restricted decryption key, TPM_ALG_NULL
	Scheme TPMTRSAScheme
	// number of bits in the public modulus
	KeyBits TPMIRSAKeyBits
	// the public exponent
	// A prime number greater than 2.
	Exponent uint32
}

// 12.2.3.6
type TPMSECCParms struct {
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size. and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric TPMTSymDefObject
	// If the sign attribute of the key is SET, then this shall be a
	// valid signing scheme.
	Scheme TPMTECCScheme
	// ECC curve ID
	CurveID TPMIECCCurve
	// an optional key derivation scheme for generating a symmetric key
	// from a Z value
	// If the kdf parameter associated with curveID is not TPM_ALG_NULL
	// then this is required to be NULL.
	KDF TPMTKDFScheme
}

// 12.2.3.7
type TPMUPublicParms struct {
	// sign | decrypt | neither
	KeyedHashDetail *TPMSKeyedHashParms `tpmdirect:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	// sign | decrypt | neither
	SymCipherDetail *TPMSSymCipherParms `tpmdirect:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	// decrypt + sign
	RSADetail *TPMSRSAParms `tpmdirect:"selector=0x0001"` // TPM_ALG_RSA
	// decrypt + sign
	ECCDetail *TPMSECCParms `tpmdirect:"selector=0x0023"` // TPM_ALG_ECC
}

// 12.2.4
type TPMTPublic struct {
	// “algorithm” associated with this object
	Type TPMIAlgPublic
	// algorithm used for computing the Name of the object
	NameAlg TPMIAlgHash
	// attributes that, along with type, determine the manipulations
	// of this object
	ObjectAttributes TPMAObject
	// optional policy for using this key
	// The policy is computed using the nameAlg of the object.
	AuthPolicy TPM2BDigest
	// the algorithm or structure details
	Parameters TPMUPublicParms `tpmdirect:"tag=Type"`
	// the unique identifier of the structure
	// For an asymmetric key, this would be the public key.
	Unique TPMUPublicID `tpmdirect:"tag=Type"`
}

// 12.2.5
type TPM2BPublic struct {
	// the public area
	PublicArea TPMTPublic `tpmdirect:"sized"`
}

// 12.3.7
type TPM2BPrivate TPM2BData

// 15.1
type TPMSCreationData struct {
	// list indicating the PCR included in pcrDigest
	PCRSelect TPMLPCRSelection
	// digest of the selected PCR using nameAlg of the object for which
	// this structure is being created
	PCRDigest TPM2BDigest
	// the locality at which the object was created
	Locality TPMALocality
	// nameAlg of the parent
	ParentNameAlg TPMAlgID
	// Name of the parent at time of creation
	ParentName TPM2BName
	// Qualified Name of the parent at the time of creation
	ParentQualifiedName TPM2BName
	// association with additional information added by the key
	OutsideInfo TPM2BData
}

// 15.2
type TPM2BCreationData struct {
	CreationData TPMSCreationData `tpmdirect:"sized"`
}
