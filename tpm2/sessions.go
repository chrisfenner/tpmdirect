package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

// pwSession represents a password-pseudo-session.
type pwSession struct {
	auth     []byte
	authName []byte
}

// PasswordAuth assembles a password pseudo-session with the given auth value.
func PasswordAuth(name, auth []byte) Session {
	return &pwSession{
		auth:     auth,
		authName: name,
	}
}

// Init is not required and has no effect for a password session.
func (s *pwSession) Init(tpm Interface) error { return nil }

// Cleanup is not required and has no effect for a password session.
func (s *pwSession) CleanupFailure(tpm Interface) error { return nil }

// NonceTPM normally returns the last nonceTPM value from the session.
// Since a password session is a pseudo-session with the auth value stuffed
// in where the HMAC should go, this is not used.
func (s *pwSession) NonceTPM() []byte { return nil }

// NewNonceCaller updates the nonceCaller for this session.
// Password sessions don't have nonces.
func (s *pwSession) NewNonceCaller() error { return nil }

// AuthorizedName returns the Name of the object being authorized.
func (s *pwSession) AuthorizedName() []byte {
	return s.authName
}

// Computes the authorization structure for the session.
func (s *pwSession) Authorize(cc TPMCC, parms, addNonces []byte, names []byte) (*TPMSAuthCommand, error) {
	return &TPMSAuthCommand{
		Handle:     TPMRSPW,
		Nonce:      TPM2BNonce{},
		Attributes: TPMASession{},
		Authorization: TPM2BData{
			Buffer: s.auth,
		},
	}, nil
}

// Validates the response session structure for the session.
func (s *pwSession) Validate(rc TPMRC, cc TPMCC, parms []byte, auth *TPMSAuthResponse) error {
	if len(auth.Nonce.Buffer) != 0 {
		return fmt.Errorf("expected empty nonce in response auth to PW session, got %x", auth.Nonce)
	}
	expectedAttrs := TPMASession{
		ContinueSession: true,
	}
	if auth.Attributes != expectedAttrs {
		return fmt.Errorf("expected only ContinueSession in response auth to PW session, got %v", auth.Attributes)
	}
	if len(auth.Authorization.Buffer) != 0 {
		return fmt.Errorf("expected empty HMAC in response auth to PW session, got %x", auth.Authorization)
	}
	return nil
}

// IsEncryption returns true if this is an encryption session.
// Password sessions can't be used for encryption.
func (s *pwSession) IsEncryption() bool { return false }

// IsDecryption returns true if this is a decryption session.
// Password sessions can't be used for decryption.
func (s *pwSession) IsDecryption() bool { return false }

// If this session is used for parameter decryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for decryption.
func (s *pwSession) Encrypt(parameter []byte) error { return nil }

// If this session is used for parameter encryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for encryption.
func (s *pwSession) Decrypt(parameter []byte) error { return nil }

// Handle returns the handle value associated with this session.
// In the case of a password session, this is always TPM_RS_PW.
func (s *pwSession) Handle() TPMHandle { return TPMRSPW }

// sessionOptions represents extra options used when setting up a session.
type sessionOptions struct {
	auth       []byte
	authName   []byte
	bindHandle TPMIDHEntity
	bindName   []byte
	bindAuth   []byte
	saltHandle TPMIDHObject
	saltPub    TPMTPublic
	attrs      TPMASession
	symmetric  TPMTSymDef
}

// defaultOptions represents the default options used when none are provided.
func defaultOptions() sessionOptions {
	return sessionOptions{
		symmetric: TPMTSymDef{
			Algorithm: TPMAlgNull,
		},
		bindHandle: TPMRHNull,
		saltHandle: TPMRHNull,
	}
}

// AuthOption is an option for setting up an auth session variadically.
type AuthOption func(*sessionOptions)

// Auth specifies the named object's auth value.
func Auth(name, auth []byte) AuthOption {
	return func(o *sessionOptions) {
		o.authName = name
		o.auth = auth
	}
}

// Auth specifies that this session's session key should depend on the auth
// value of the given object.
func Bound(handle TPMIDHEntity, name, auth []byte) AuthOption {
	return func(o *sessionOptions) {
		o.bindHandle = handle
		o.bindName = name
		o.bindAuth = auth
	}
}

// Salted specifies that this session's session key should depend on an
// encrypted seed value using the given public key.
func Salted(handle TPMIDHObject, pub TPMTPublic) AuthOption {
	return func(o *sessionOptions) {
		o.saltHandle = handle
		o.saltPub = pub
	}
}

// parameterEncryptionDirection specifies whether the session-encrypted parameters
// are encrypted on the way into the TPM, out of the TPM, or both.
type parameterEncryptionDirection int

const (
	EncryptIn parameterEncryptionDirection = 1 + iota
	EncryptOut
	EncryptInOut
)

// AESEncryption uses the session to encrypt the first parameter sent to/from the TPM.
// Note that only commands whose first command/response parameter is a 2B can
// support session encryption.
func AESEncryption(keySize TPMKeyBits, dir parameterEncryptionDirection) AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Decrypt = (dir == EncryptIn || dir == EncryptInOut)
		o.attrs.Encrypt = (dir == EncryptOut || dir == EncryptInOut)
		o.symmetric = TPMTSymDef{
			Algorithm: TPMAlgAES,
			KeyBits: TPMUSymKeyBits{
				AES: NewTPMKeyBits(keySize),
			},
			Mode: TPMUSymMode{
				AES: NewTPMAlgID(TPMAlgCFB),
			},
		}
	}
}

// Audit uses the session to compute extra HMACs.
// An Audit session can be used with GetSessionAuditDigest to obtain attestation
// over a sequence of commands.
func Audit() AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Audit = true
	}
}

// AuditExclusive is like an audit session, but even more powerful.
// This allows an audit session to additionally indicate that no other auditable
// commands were executed other than the ones described by the audit hash.
func AuditExclusive() AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Audit = true
		o.attrs.AuditExclusive = true
	}
}

// hmacSession generally implements the HMAC session.
type hmacSession struct {
	sessionOptions
	hash       TPMIAlgHash
	nonceSize  int
	handle     TPMHandle
	sessionKey []byte
	// last nonceCaller
	nonceCaller TPM2BNonce
	// last nonceTPM
	nonceTPM TPM2BNonce
}

// HMAC sets up a just-in-time HMAC session that is used only once.
// A real session is created, but just in time and it is flushed when used.
func HMAC(hash TPMIAlgHash, nonceSize int, opts ...AuthOption) Session {
	// Set up a one-off session that knows the auth value.
	sess := hmacSession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         TPMRHNull,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}
	return &sess
}

// HMACSession sets up a reusable HMAC session that needs to be closed.
func HMACSession(tpm Interface, hash TPMIAlgHash, nonceSize int, opts ...AuthOption) (s Session, close func() error, err error) {
	// Set up a not-one-off session that knows the auth value.
	sess := hmacSession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         TPMRHNull,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}
	// This session is reusable and is closed with the function we'll return.
	sess.sessionOptions.attrs.ContinueSession = true

	// Initialize the session.
	if err := sess.Init(tpm); err != nil {
		return nil, nil, err
	}

	closer := func() error {
		flushCmd := FlushContextCommand{
			FlushHandle: sess.handle,
		}
		var flushRsp FlushContextResponse
		return tpm.Execute(&flushCmd, &flushRsp)
	}

	return &sess, closer, nil
}

// Part 1, B.10.2
func getEncryptedSaltRSA(nameAlg TPMIAlgHash, parms *TPMSRSAParms, pub *TPM2BPublicKeyRSA) (*TPM2BEncryptedSecret, []byte, error) {
	rsaPub, err := rsaPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to RSA key: %w", err)
	}
	// Odd special case: the size of the salt depends on the RSA scheme's hash alg.
	var hAlg TPMIAlgHash
	switch parms.Scheme.Scheme {
	case TPMAlgRSASSA:
		hAlg = parms.Scheme.Details.RSASSA.HashAlg
	case TPMAlgRSAES:
		hAlg = nameAlg
	case TPMAlgRSAPSS:
		hAlg = parms.Scheme.Details.RSAPSS.HashAlg
	case TPMAlgOAEP:
		hAlg = parms.Scheme.Details.OAEP.HashAlg
	case TPMAlgNull:
		hAlg = nameAlg
	default:
		return nil, nil, fmt.Errorf("unsupported RSA salt key scheme: %v", parms.Scheme.Scheme)
	}
	salt := make([]byte, hAlg.Hash().Size())
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generating random salt: %w", err)
	}
	// Part 1, section 4.6 specifies the trailing NULL byte for the label.
	encSalt, err := rsa.EncryptOAEP(hAlg.Hash(), rand.Reader, rsaPub, salt, []byte("SECRET\x00"))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting salt: %w", err)
	}
	return &TPM2BEncryptedSecret{
		Buffer: encSalt,
	}, salt, nil
}

// Part 1, 19.6.13
func getEncryptedSaltECC(nameAlg TPMIAlgHash, parms *TPMSECCParms, pub *TPMSECCPoint) (*TPM2BEncryptedSecret, []byte, error) {
	curve, err := parms.CurveID.Curve()
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	eccPub, err := eccPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	ephPriv, ephPubX, ephPubY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	zx, _ := curve.Params().ScalarMult(eccPub.x, eccPub.y, ephPriv)
	salt := KDFe(nameAlg, zx.Bytes(), []byte("SECRET\x00"), ephPubX.Bytes(), pub.X.Buffer, nameAlg.Hash().Size())

	var encSalt bytes.Buffer
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubX.Bytes())))
	encSalt.Write(ephPubX.Bytes())
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubY.Bytes())))
	encSalt.Write(ephPubY.Bytes())
	return &TPM2BEncryptedSecret{
		Buffer: encSalt.Bytes(),
	}, salt, nil
}

// getEncryptedSalt creates a salt value for salted sessions.
// Returns the encrypted salt and plaintext salt, or an error value.
func getEncryptedSalt(pub TPMTPublic) (*TPM2BEncryptedSecret, []byte, error) {
	switch pub.Type {
	case TPMAlgRSA:
		return getEncryptedSaltRSA(pub.NameAlg, pub.Parameters.RSADetail, pub.Unique.RSA)
	case TPMAlgECC:
		return getEncryptedSaltECC(pub.NameAlg, pub.Parameters.ECCDetail, pub.Unique.ECC)
	default:
		return nil, nil, fmt.Errorf("salt encryption alg '%v' not supported", pub.Type)
	}
}

// Init initializes the session, just in time, if needed.
func (s *hmacSession) Init(tpm Interface) error {
	if s.handle != TPMRHNull {
		// Session is already initialized.
		return nil
	}

	// Get a high-quality nonceCaller for our use.
	// Store it with the session object for later reference.
	s.nonceCaller = TPM2BNonce{
		Buffer: make([]byte, s.nonceSize),
	}
	if _, err := rand.Read(s.nonceCaller.Buffer); err != nil {
		return err
	}

	// Start up the actual auth session.
	sasCmd := StartAuthSessionCommand{
		TPMKey:      s.saltHandle,
		Bind:        s.bindHandle,
		NonceCaller: s.nonceCaller,
		SessionType: TPMSEHMAC,
		Symmetric:   s.symmetric,
		AuthHash:    s.hash,
	}
	var salt []byte
	if s.saltHandle != TPMRHNull {
		var err error
		var encSalt *TPM2BEncryptedSecret
		encSalt, salt, err = getEncryptedSalt(s.saltPub)
		if err != nil {
			return err
		}
		sasCmd.EncryptedSalt = *encSalt
	}
	var sasRsp StartAuthSessionResponse
	if err := tpm.Execute(&sasCmd, &sasRsp); err != nil {
		return err
	}
	s.handle = sasRsp.SessionHandle
	s.nonceTPM = sasRsp.NonceTPM
	var authSalt []byte
	authSalt = append(authSalt, s.bindAuth...)
	authSalt = append(authSalt, salt...)
	// Part 1, 19.6
	if len(authSalt) != 0 {
		s.sessionKey = KDFA(s.hash, authSalt, []byte("ATH"), s.nonceTPM.Buffer, s.nonceCaller.Buffer, s.hash.Hash().Size())
	}
	return nil
}

// Cleanup cleans up the session, if needed.
func (s *hmacSession) CleanupFailure(tpm Interface) error {
	// The user is already responsible to clean up this session.
	if s.attrs.ContinueSession {
		return nil
	}
	flushCmd := FlushContextCommand{
		FlushHandle: s.handle,
	}
	var flushRsp FlushContextResponse
	if err := tpm.Execute(&flushCmd, &flushRsp); err != nil {
		return err
	}
	s.handle = TPMRHNull
	return nil
}

// NonceTPM returns the last nonceTPM value from the session.
// May be nil, if the session hasn't been initialized yet.
func (s *hmacSession) NonceTPM() []byte { return s.nonceTPM.Buffer }

// To avoid a depenency on tpmdirect by tpm2, implement a tiny serialization by hand for TPMASession here
func attrsToBytes(attrs TPMASession) []byte {
	var res byte
	if attrs.ContinueSession {
		res |= (1 << 0)
	}
	if attrs.AuditExclusive {
		res |= (1 << 1)
	}
	if attrs.AuditReset {
		res |= (1 << 2)
	}
	if attrs.Reserved1 {
		res |= (1 << 3)
	}
	if attrs.Reserved2 {
		res |= (1 << 4)
	}
	if attrs.Decrypt {
		res |= (1 << 5)
	}
	if attrs.Encrypt {
		res |= (1 << 6)
	}
	if attrs.Audit {
		res |= (1 << 7)
	}
	return []byte{res}
}

// computeHMAC computes an authorization HMAC according to various equations in Part 1.
// This applies to both commands and responses.
// The value of key depends on whether the session is bound and/or salted.
// parms is the data that goes into cpHash for a command, or an rpHash for a response.
//     For a command, this is (CommandCode || Name(s) || Parameter area)
//     For a response, this is (ResponseCode || CommandCode || Parameter area)
// nonceNewer in a command is the new nonceCaller sent in the command session packet.
// nonceNewer in a response is the new nonceTPM sent in the response session packet.
// nonceOlder in a command is the last nonceTPM sent by the TPM for this session.
//     This may be when the session was created, or the last time it was used.
// nonceOlder in a response is the corresponding nonceCaller sent in the command.
func computeHMAC(alg TPMIAlgHash, key, parms, nonceNewer, nonceOlder, addNonces []byte, attrs TPMASession) ([]byte, error) {
	h := alg.Hash()
	h.Write(parms)
	pHash := h.Sum(nil)
	mac := hmac.New(alg.Hash, key)
	mac.Write(pHash)
	mac.Write(nonceNewer)
	mac.Write(nonceOlder)
	mac.Write(addNonces)
	mac.Write(attrsToBytes(attrs))
	return mac.Sum(nil), nil
}

// Trim trailing zeros from the auth value. Part 1, 19.6.5, Note 2
// Does not allocate a new underlying byte array.
func hmacKeyFromAuthValue(auth []byte) []byte {
	key := auth
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == 0 {
			key = key[:i]
		}
	}
	return key
}

// NewNonceCaller updates the nonceCaller for this session.
func (s *hmacSession) NewNonceCaller() error {
	_, err := rand.Read(s.nonceCaller.Buffer)
	return err
}

// AuthorizedName returns the Name of the object being authorized.
func (s *hmacSession) AuthorizedName() []byte {
	return s.authName
}

// Computes the authorization structure for the session.
func (s *hmacSession) Authorize(cc TPMCC, parms, addNonces []byte, names []byte) (*TPMSAuthCommand, error) {
	if s.handle == TPMRHNull {
		// Session is not initialized.
		return nil, fmt.Errorf("session not initialized")
	}
	// Calculate the parameter buffer for the HMAC.
	var parmBuf bytes.Buffer
	binary.Write(&parmBuf, binary.BigEndian, cc)
	parmBuf.Write(names)
	parmBuf.Write(parms)

	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	if !bytes.Equal(s.authName, s.bindName) {
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	}

	// Compute the authorization HMAC.
	hmac, err := computeHMAC(s.hash, hmacKey, parmBuf.Bytes(),
		s.nonceCaller.Buffer, s.nonceTPM.Buffer, addNonces, s.attrs)
	if err != nil {
		return nil, err
	}
	result := TPMSAuthCommand{
		Handle:     s.handle,
		Nonce:      s.nonceCaller,
		Attributes: s.attrs,
		Authorization: TPM2BData{
			Buffer: hmac,
		},
	}
	return &result, nil
}

// Validates the response session structure for the session.
// Updates nonceTPM from the TPM's response.
func (s *hmacSession) Validate(rc TPMRC, cc TPMCC, parms []byte, auth *TPMSAuthResponse) error {
	// Track the new nonceTPM for the session.
	s.nonceTPM = auth.Nonce
	// Calculate the parameter buffer for the HMAC.
	var parmBuf bytes.Buffer
	binary.Write(&parmBuf, binary.BigEndian, rc)
	binary.Write(&parmBuf, binary.BigEndian, cc)
	parmBuf.Write(parms)

	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	if !bytes.Equal(s.authName, s.bindName) {
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	}

	// Compute the authorization HMAC.
	mac, err := computeHMAC(s.hash, hmacKey, parmBuf.Bytes(),
		s.nonceTPM.Buffer, s.nonceCaller.Buffer, nil, auth.Attributes)
	if err != nil {
		return err
	}
	// Compare the HMAC (constant time)
	if !hmac.Equal(mac, auth.Authorization.Buffer) {
		return fmt.Errorf("incorrect authorization HMAC")
	}
	return nil
}

// IsEncryption returns true if this is an encryption session.
func (s *hmacSession) IsEncryption() bool {
	return s.attrs.Encrypt
}

// IsDecryption returns true if this is a decryption session.
func (s *hmacSession) IsDecryption() bool {
	return s.attrs.Decrypt
}

// If this session is used for parameter decryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
func (s *hmacSession) Encrypt(parameter []byte) error {
	if !s.IsDecryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	bits := int(keyBytes) + 16
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	keyIV := KDFA(s.hash, sessionValue, []byte("CFB"), s.nonceCaller.Buffer, s.nonceTPM.Buffer, bits)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBEncrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// If this session is used for parameter encryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
func (s *hmacSession) Decrypt(parameter []byte) error {
	if !s.IsEncryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	bits := int(keyBytes) + 16
	// Part 1, 21.1
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	keyIV := KDFA(s.hash, sessionValue, []byte("CFB"), s.nonceTPM.Buffer, s.nonceCaller.Buffer, bits)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// Handle returns the handle value of the session.
// If the session is created with HMAC (instead of HMACSession) this will be TPM_RH_NULL.
func (s *hmacSession) Handle() TPMHandle {
	return s.handle
}
