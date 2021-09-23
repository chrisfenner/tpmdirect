package tpm2

import (
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
	// Initializes the session, if needed. Has no effect if not needed or
	// already done. Some types of sessions may need to be initialized
	// just-in-time, e.g., to support calling patterns that help the user
	// securely authorize their actions without writing a lot of code.
	Init(tpm Interface) error
	// Cleans up the session, if needed.
	// Some types of session need to be cleaned up if the command failed,
	// again to support calling patterns that help the user securely
	// authorize their actions without writing a lot of code.
	CleanupFailure(tpm Interface) error
	// The last nonceTPM for this session.
	NonceTPM() []byte
	// Updates nonceCaller to a new random value.
	NewNonceCaller() error
	// Computes the authorization HMAC for the session.
	// If this is the first authorization session for a command, and
	// there is another session (or sessions) for parameter
	// decryption and/or encryption, then addNonces contains the
	// nonceTPMs from each of them, respectively (see Part 1, 19.6.5)
	Authorize(cc TPMCC, parms, addNonces []byte, names []TPM2BName) (*TPMSAuthCommand, error)
	// Validates the response for the session.
	// Updates NonceTPM for the session, and generates a new NonceCaller.
	Validate(rc TPMRC, cc TPMCC, parms []byte, auth *TPMSAuthResponse) error
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
	io.Closer
	// Dispatch serializes a request struct, sends it to the TPM, and then
	// deserializes the response struct.
	// sessions may be 0 to three Session objects. See the TPM
	// specification for what types of sessions are supported.
	// An error inside the TPM response stream is parsed at this layer.
	Execute(cmd Command, rsp Response, sess ...Session) error
}
