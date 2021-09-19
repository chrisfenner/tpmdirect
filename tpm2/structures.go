package tpm2

// Part 1 structures that aren't defined in Part 2
type TPMCmdHeader struct {
	Tag         TPMISTCommandTag
	Length      uint16
	CommandCode TPMCC
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

// 7.1
type TPMHandle uint32

// 8.3.2
type TPMAObject struct {
	// shall be zero
	Reserved1 uint8 `tpm2:"bit=0"`
	// SET (1): The hierarchy of the object, as indicated by its
	// Qualified Name, may not change.
	// CLEAR (0): The hierarchy of the object may change as a result
	// of this object or an ancestor key being duplicated for use in
	// another hierarchy.
	FixedTPM uint8 `tpm2:"bit=1"`
	// SET (1): Previously saved contexts of this object may not be
	// loaded after Startup(CLEAR).
	// CLEAR (0): Saved contexts of this object may be used after a
	// Shutdown(STATE) and subsequent Startup().
	STClear uint8 `tpm2:"bit=2"`
	// shall be zero
	Reserved2 uint8 `tpm2:"bit=3"`
	// SET (1): The parent of the object may not change.
	// CLEAR (0): The parent of the object may change as the result of
	// a TPM2_Duplicate() of the object.
	FixedParent uint8 `tpm2:"bit=4"`
	// SET (1): Indicates that, when the object was created with
	// TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of
	// the sensitive data other than the authValue.
	// CLEAR (0): A portion of the sensitive data, other than the
	// authValue, was provided by the caller.
	SensitiveDataOrigin uint8 `tpm2:"bit=5"`
	// SET (1): Approval of USER role actions with this object may be
	// with an HMAC session or with a password using the authValue of
	// the object or a policy session.
	// CLEAR (0): Approval of USER role actions with this object may
	// only be done with a policy session.
	UserWithAuth uint8 `tpm2:"bit=6"`
	// SET (1): Approval of ADMIN role actions with this object may
	// only be done with a policy session.
	// CLEAR (0): Approval of ADMIN role actions with this object may
	// be with an HMAC session or with a password using the authValue
	// of the object or a policy session.
	AdminWithPolicy uint8 `tpm2:"bit=7"`
	// shall be zero
	Reserved3 uint8 `tpm2:"bit=9:8"`
	// SET (1): The object is not subject to dictionary attack
	// protections.
	// CLEAR (0): The object is subject to dictionary attack
	// protections.
	NoDA uint8 `tpm2:"bit=10"`
	// SET (1): If the object is duplicated, then symmetricAlg shall
	// not be TPM_ALG_NULL and newParentHandle shall not be
	// TPM_RH_NULL.
	// CLEAR (0): The object may be duplicated without an inner
	// wrapper on the private portion of the object and the new parent
	// may be TPM_RH_NULL.
	EncryptedDuplication uint8 `tpm2:"bit=11"`
	// shall be zero
	Reserved4 uint8 `tpm2:"bit=15:12"`
	// SET (1): Key usage is restricted to manipulate structures of
	// known format; the parent of this key shall have restricted SET.
	// CLEAR (0): Key usage is not restricted to use on special
	// formats.
	Restricted uint8 `tpm2:"bit=16"`
	// SET (1): The private portion of the key may be used to decrypt.
	// CLEAR (0): The private portion of the key may not be used to
	// decrypt.
	Decrypt uint8 `tpm2:"bit=17"`
	// SET (1): For a symmetric cipher object, the private portion of
	// the key may be used to encrypt. For other objects, the private
	// portion of the key may be used to sign.
	// CLEAR (0): The private portion of the key may not be used to
	// sign or encrypt.
	SignEncrypt uint8 `tpm2:"bit=18"`
	// SET (1): An asymmetric key that may not be used to sign with
	// TPM2_Sign() CLEAR (0): A key that may be used with TPM2_Sign()
	// if sign is SET
	// NOTE: This attribute only has significance if sign is SET.
	X509Sign uint8 `tpm2:"bit=19"`
	// shall be zero
	Reserved5 uint8 `tpm2:"bit=23:20"`
	// shall be zero
	Reserved6 uint8 `tpm2:"bit=31:24"`
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
	ContinueSession uint8 `tpm2:"bit=0"`
	// SET (1): In a command, this setting indicates that the command
	// should only be executed if the session is exclusive at the start of
	// the command. In a response, it indicates that the session is
	// exclusive. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the session need not be
	// exclusive at the start of the command. In a response, indicates that
	// the session is not exclusive.
	AuditExclusive uint8 `tpm2:"bit=1"`
	// SET (1): In a command, this setting indicates that the audit digest
	// of the session should be initialized and the exclusive status of the
	// session SET. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the audit digest should not
	// be initialized. This bit is always CLEAR in a response.
	AuditReset uint8 `tpm2:"bit=2"`
	// shall be CLEAR
	Reserved1 uint8 `tpm2:"bit=4:3"`
	// SET (1): In a command, this setting indicates that the first
	// parameter in the command is symmetrically encrypted using the
	// parameter encryption scheme described in TPM 2.0 Part 1. The TPM will
	// decrypt the parameter after performing any HMAC computations and
	// before unmarshaling the parameter. In a response, the attribute is
	// copied from the request but has no effect on the response.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Decrypt uint8 `tpm2:"bit=5"`
	// SET (1): In a command, this setting indicates that the TPM should use
	// this session to encrypt the first parameter in the response. In a
	// response, it indicates that the attribute was set in the command and
	// that the TPM used the session to encrypt the first parameter in the
	// response using the parameter encryption scheme described in TPM 2.0
	// Part 1.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Encrypt uint8 `tpm2:"bit=6"`
	// SET (1): In a command or response, this setting indicates that the
	// session is for audit and that auditExclusive and auditReset have
	// meaning. This session may also be used for authorization, encryption,
	// or decryption. The encrypted and encrypt fields may be SET or CLEAR.
	// CLEAR (0): Session is not used for audit.
	// If SET in the command, then this attribute will be SET in the response.
	Audit uint8 `tpm2:"bit=7"`
}

// 8.5
type TPMALocality struct {
	TPMLocZero  uint8 `tpm2:"bit=0"`
	TPMLocOne   uint8 `tpm2:"bit=1"`
	TPMLocTwo   uint8 `tpm2:"bit=2"`
	TPMLocThree uint8 `tpm2:"bit=3"`
	TPMLocFour  uint8 `tpm2:"bit=4"`
	// If any of these bits is set, an extended locality is indicated
	Extended uint8 `tpm2:"bit=7:5"`
}

// 9.3
type TPMIDHObject = TPMHandle

// 9.8
type TPMISHAuthSession = TPMHandle

// 9.11
type TPMIDHContext = TPMHandle

// 9.13
type TPMIRHHierarchy = TPMHandle

// 9.27
type TPMIAlgHash = TPMAlgID

// 9.30
type TPMIAlgSymObject = TPMAlgID

// 9.31
type TPMIAlgSymMode = TPMAlgID

// 9.32
type TPMIAlgKDF = TPMAlgID

// 9.35
type TPMISTCommandTag = TPMST

// 10.1
type TPMSEmpty = struct{}

// 10.4.2
type TPM2BDigest struct {
	// size in octets of the buffer field; may be 0
	Buffer []byte `tpm2:"sized"`
}

// 10.4.3
type TPM2BData struct {
	// size in octets of the buffer field; may be 0
	Buffer []byte `tpm2:"sized"`
}

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
	PCRSelect TPM2BData
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

// 10.9.7
type TPMLPCRSelection struct {
	PCRSelections []TPMSPCRSelection `tpm2:"list"`
}

// 10.13.2
type TPMSAuthCommand struct {
	handle        TPMISHAuthSession
	nonce         TPM2BData
	attributes    TPMASession
	authorization TPM2BData
}

// 10.13.3
type TPMSAuthResponse struct {
	nonce         TPM2BData
	attributes    TPMASession
	authorization TPM2BData
}

// 11.1.3
type TPMUSymKeyBits struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMKeyBits  `tpm2:"selector=TPMAlgAES"`
	XOR *TPMIAlgHash `tpm2:"selector=TPMAlgXOR"`
}

// 11.1.4
type TPMUSymMode struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMIAlgSymMode `tpm2:"selector=TPMAlgAES"`
	XOR *struct{}       `tpm2:"selector=TPMAlgXOR"`
}

// 11.1.5
type TPMUSymDetails struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *struct{} `tpm2:"selector=TPMAlgAES"`
	XOR *struct{} `tpm2:"selector=TPMAlgXOR"`
}

// 11.1.7
type TPMTSymDefObject struct {
	// selects a symmetric block cipher
	// When used in the parameter area of a parent object, this shall
	// be a supported block cipher and not TPM_ALG_NULL
	Algorithm TPMIAlgSymObject
	// the key size
	KeyBits TPMUSymKeyBits `tpm2:"tag=Algorithm"`
	// default mode
	// When used in the parameter area of a parent object, this shall
	// be TPM_ALG_CFB.
	Mode TPMUSymMode `tpm2:"tag=Algorithm"`
	// contains the additional algorithm details, if any
	Details TPMUSymDetails `tpm2:"tag=Algorithm"`
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
	Sensitive TPMSSensitiveCreate `tpm2:"sized"`
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
	HMAC *TPMSSchemeHMAC `tpm2:"selector=TPMAlgHMAC"`
	XOR  *TPMSSchemeXOR  `tpm2:"selector=TPMAlgXOR"`
}

// 11.1.23
type TPMTKeyedHashScheme struct {
	Scheme  TPMIAlgKeyedHashScheme
	Details TPMUSchemeKeyedHash `tpm2:"tag=Scheme"`
}

// 11.2.1.2
type TPMSSigSchemeRSASSA TPMSSchemeHash
type TPMSSigSchemeRSAPSS TPMSSchemeHash

// 11.2.1.3
type TPMSSigSchemeECDSA TPMSSchemeHash

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
	MGF1         *TPMSKDFSchemeMGF1         `tpm2:"selector=TPMAlgMGF1"`
	ECDH         *TPMSKDFSchemeECDH         `tpm2:"selector=TPMAlgECDH"`
	KDF1SP80056A *TPMSKDFSchemeKDF1SP80056A `tpm2:"selector=TPMAlgKDF1SP80056A"`
	KDF2         *TPMSKDFSchemeKDF2         `tpm2:"selector=TPMAlgKDF2"`
	KDF1SP800108 *TPMSKDFSchemeKDF1SP800108 `tpm2:"selector=TPMAlgKDF1SP80056A"`
}

// 11.2.3.3
type TPMTKDFScheme struct {
	// scheme selector
	Scheme TPMIAlgKDF
	// scheme parameters
	Details TPMUKDFScheme `tpm2:"tag=Scheme"`
}

// 11.2.3.5
type TPMUAsymScheme struct {
	// TODO every asym scheme gets an entry in this union.
	RSASSA *TPMSSigSchemeRSASSA `tpm2:"selector=TPMAlgRSASSA"`
	RSAES  *TPMSEncSchemeRSAES  `tpm2:"selector=TPMAlgRSAES"`
	RSAPSS *TPMSSigSchemeRSAPSS `tpm2:"selector=TPMAlgRSAPSS"`
	OAEP   *TPMSEncSchemeOAEP   `tpm2:"selector=TPMAlgOAEP"`
	ECDSA  *TPMSSigSchemeECDSA  `tpm2:"selector=TPMAlgECDSA"`
	ECDH   *TPMSKeySchemeECDH   `tpm2:"selector=TPMAlgECDH"`
}

// 11.2.4.1
type TPMIAlgRSAScheme = TPMAlgID

// 11.2.4.2
type TPMTRSAScheme struct {
	// scheme selector
	Scheme TPMIAlgRSAScheme
	// scheme parameters
	Details TPMUAsymScheme `tpm2:"tag=Scheme"`
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
	Scheme TPMIAlgECCScheme
	// scheme parameters
	Details TPMUAsymScheme `tpm2:"tag=Scheme"`
}

// 12.2.2
type TPMIAlgPublic = TPMAlgID

// 12.2.3.2
type TPMUPublicID struct {
	KeyedHash *TPM2BDigest       `tpm2:"selector=TPMAlgKeyedHash"`
	Sym       *TPM2BDigest       `tpm2:"selector=TPMAlgSymCipher"`
	RSA       *TPM2BPublicKeyRSA `tpm2:"selector=TPMAlgRSA"`
	ECC       *TPMSECCPoint      `tpm2:"selector=TPMAlgECC"`
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
	KeyedHashDetail *TPMSKeyedHashParms `tpm2:"selector=TPMAlgKeyedHash"`
	// sign | decrypt | neither
	SymCipherDetail *TPMSSymCipherParms `tpm2:"selector=TPMAlgSymCipher"`
	// decrypt + sign
	RSADetail *TPMSRSAParms `tpm2:"selector=TPMAlgRSA"`
	// decrypt + sign
	ECCDetail *TPMSECCParms `tpm2:"selector=TPMAlgECC"`
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
	Parameters TPMUPublicParms `tpm2:"tag=Type"`
	// the unique identifier of the structure
	// For an asymmetric key, this would be the public key.
	Unique TPMUPublicID `tpm2:"tag=Type"`
}

// 12.2.5
type TPM2BPublic struct {
	// the public area
	PublicArea TPMTPublic `tpm2:"sized"`
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
	CreationData TPMSCreationData `tpm2:"sized"`
}
