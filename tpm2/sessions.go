package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// pwSession represents a password-pseudo-session.
type pwSession struct {
	auth []byte
}

// PasswordAuth assembles a password pseudo-session with the given auth value.
func PasswordAuth(auth []byte) Session {
	return &pwSession{
		auth: auth,
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

// Computes the authorization structure for the session.
func (s *pwSession) Authorize(cc TPMCC, parms, decrypt, encrypt []byte, names []TPM2BName) (*TPMSAuthCommand, error) {
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

// authOptions represents extra options used when setting up a session.
type authOptions struct {
	encryption bool
	decryption bool
	symmetric TPMTSymDef
}

// defaultOptions represents the default options used when none are provided.
func defaultOptions() authOptions {
	return authOptions{
		symmetric: TPMTSymDef{
			Algorithm: TPMAlgNull,
		},
	}
}

// AuthOption is an option for setting up an auth session variadically.
type AuthOption func(*authOptions)

// AES encryption uses the session to encrypt the first parameter returned from the TPM.
// Multiple AESEncrypt/AESDecrypt calls will take the key size of the last one provided.
func AESEncrypt(keySize TPMKeyBits) AuthOption {
	return func(o *authOptions) {
		o.encryption = true
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

// AES encryption uses the session to encrypt the first parameter provided to the TPM.
// Multiple AESEncrypt/AESDecrypt calls will take the key size of the last one provided.
func AESDecrypt(keySize TPMKeyBits) AuthOption {
	return func(o *authOptions) {
		o.decryption = true
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

// hmacSession generally implements the HMAC session.
type hmacSession struct {
	hash      TPMIAlgHash
	nonceSize int
	handle    TPMHandle
	auth      []byte
	attrs     TPMASession
	// last nonceCaller
	nonceCaller TPM2BNonce
	// last nonceTPM
	nonceTPM TPM2BNonce
	symmetric TPMTSymDef
}

// HMACAuth sets up a just-in-time HMAC session that is used only once.
// A real session is created, but just in time and it is flushed when used.
func HMACAuth(hash TPMIAlgHash, nonceSize int, auth []byte, opts ...AuthOption) Session {
	// Set up a one-off session that knows the auth value.
	sess := hmacSession{
		hash:      hash,
		nonceSize: nonceSize,
		handle:    TPMRHNull,
		auth:      auth,
		attrs: TPMASession{
			ContinueSession: false,
		},
	}
	// Start with the default options, then apply any that were provided.
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	sess.symmetric = o.symmetric
	sess.attrs.Encrypt = o.encryption
	sess.attrs.Decrypt = o.decryption
	return &sess
}

// HMACSession sets up a reusable HMAC session that needs to be closed.
func HMACSession(tpm Interface, hash TPMIAlgHash, nonceSize int, auth []byte, opts ...AuthOption) (s Session, close func() error, err error) {
	// Set up a not-one-off session that knows the auth value.
	sess := hmacSession{
		hash:      hash,
		nonceSize: nonceSize,
		handle:    TPMRHNull,
		auth:      auth,
		attrs: TPMASession{
			ContinueSession: true,
		},
	}
	// Start with the default options, then apply any that were provided.
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	sess.symmetric = o.symmetric
	sess.attrs.Encrypt = o.encryption
	sess.attrs.Decrypt = o.decryption

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
		TPMKey:      TPMRHNull,
		Bind:        TPMRHNull,
		NonceCaller: s.nonceCaller,
		SessionType: TPMSEHMAC,
		Symmetric: s.symmetric,
		AuthHash: s.hash,
	}
	var sasRsp StartAuthSessionResponse
	if err := tpm.Execute(&sasCmd, &sasRsp); err != nil {
		return err
	}
	s.handle = sasRsp.SessionHandle
	s.nonceTPM = sasRsp.NonceTPM
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
func computeHMAC(alg TPMIAlgHash, key, parms, nonceNewer, nonceOlder []byte, attrs TPMASession) ([]byte, error) {
	h := alg.Hash()
	h.Write(parms)
	pHash := h.Sum(nil)
	mac := hmac.New(alg.Hash, key)
	mac.Write(pHash)
	mac.Write(nonceNewer)
	mac.Write(nonceOlder)
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

// Computes the authorization structure for the session.
// Updates nonceCaller to be a new random nonce.
func (s *hmacSession) Authorize(cc TPMCC, parms, decrypt, encrypt []byte, names []TPM2BName) (*TPMSAuthCommand, error) {
	if s.handle == TPMRHNull {
		// Session is not initialized.
		return nil, fmt.Errorf("session not initialized")
	}
	// Generate a new nonceCaller for the command.
	// Calculate the parameter buffer for the HMAC.
	var parmBuf bytes.Buffer
	binary.Write(&parmBuf, binary.BigEndian, cc)
	for _, name := range names {
		parmBuf.Write(name.Buffer)
	}
	parmBuf.Write(parms)

	key := hmacKeyFromAuthValue(s.auth)
	// Compute the authorization HMAC.
	hmac, err := computeHMAC(s.hash, key, parmBuf.Bytes(), s.nonceCaller.Buffer, s.nonceTPM.Buffer, s.attrs)
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

	key := hmacKeyFromAuthValue(s.auth)
	// Compute the authorization HMAC.
	mac, err := computeHMAC(s.hash, key, parmBuf.Bytes(), s.nonceTPM.Buffer, s.nonceCaller.Buffer, auth.Attributes)
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
	if !s.IsDecryption() { return nil }
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES/8
	bits := int(keyBytes) + 16
	keyIV := KDFA(s.hash, s.auth, []byte("CFB"), s.nonceCaller.Buffer, s.nonceTPM.Buffer, bits)
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
	if !s.IsEncryption() { return nil }
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES/8
	bits := int(keyBytes) + 16
	keyIV := KDFA(s.hash, s.auth, []byte("CFB"), s.nonceTPM.Buffer, s.nonceCaller.Buffer, bits)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}
