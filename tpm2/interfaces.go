package tpm2

import (
	"hash"
	"io"
)

// Transport represents a physical connection to a TPM.
type Transport interface {
	io.Closer
	// Send sends a command stream to the TPM and receives back a response.
	// Errors from the TPM itself (i.e., in the response stream) are not
	// parsed. Only errors from actually sending the command.
	Send(command []byte) ([]byte, error)
}

// Session represents a session in the TPM.
type Session interface {
	// Returns the hash algorithm associated with this session.
	AuthHash() hash.Hash
	// The length of nonces for this session.
	NonceSize() int
	// The last nonceTPM for this session.
	NonceTPM() []byte
	// Updates NonceTPM for the session, and generates a new NonceCaller.
	Update(nonceTPM []byte) error
	// Computes the authorization HMAC for the session.
	// If this is the first authorization session for a command, and
	// there is another session (or sessions) for parameter
	// encryption and decryption, then decrypt and encrypt are non-nil
	// and contain nonceTPM from each of those sessions, respectively.
	Authorize(cc TPMCC, parms, decrypt, encrypt []byte, names []TPM2BName) (*TPMSAuthCommand, error)
	// Validates the response HMAC for the session.
	Validate(rc TPMRC, cc TPMCC, parms []byte, auth TPMSAuthResponse) error
	// Returns true if this is an encryption session.
	IsEncryption() bool
	// Returns true if this is a decryption session.
	IsDecryption() bool
	// If this session is used for parameter decryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Encrypt(parameter []byte) error
	// If this session is used for parameter encryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Decrypt(parameter []byte) error
}

// Interface represents a logical connection to a TPM.
type Interface interface {
	// Dispatch serializes a request struct, sends it to the TPM, and then
	// deserializes the response struct.
	// sessions may be 0 to three Session objects. See the TPM
	// specification for what types of sessions are supported.
	// An error inside the TPM response stream is parsed at this layer.
	Dispatch(cmd Command, rsp Response, sess ...Session) error
}
