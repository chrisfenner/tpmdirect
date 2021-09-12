package tpm2

import "hash"

// Transport represents a physical connection to a TPM.
type Transport interface {
	// Send sends a command stream to the TPM and receives back a response.
	// Errors from the TPM itself (i.e., in the response stream) are not
	// parsed. Only errors from actually sending the command.
	Send(command []byte) ([]byte, error)
}

// Session represents a session in the TPM.
type Session interface {
	// Returns the hash algorithm associated with this session.
	AuthHash() hash.Hash
	// If this session is used for parameter decryption, returns the
	// nonceTPM from this session. Otherwise, returns nil.
	NonceTPMDecrypt() []byte
	// If this session is used for parameter encryption, returns the
	// nonceTPM from this session. Otherwise, returns nil.
	NonceTPMEncrypt() []byte
	// Computes the authorization HMAC for the session.
	// If this is the first authorization session for a command, and
	// there is another session (or sessions) for parameter
	// encryption and decryption, then decrypt and encrypt are non-nil
	// and contain nonceTPM from each of those sessions, respectively.
	Authorize(cpHash, nonceCaller, decrypt, encrypt []byte) ([]byte, error)
	// Validates the response HMAC for the session.
	Validate(rpHash, nonceCaller, hmac []byte) error
	// If this session is used for parameter decryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Encrypt(nonceCaller, parameter []byte) error
	// If this session is used for parameter decryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Decrypt(nonceCaller, parameter []byte) error
}

// Interface represents a logical connection to a TPM.
type Interface interface {
	// Dispatch serializes a request struct, sends it to the TPM, and then
	// deserializes the response struct.
	// sessions may be 0 to three Session objects. See the TPM
	// specification for what types of sessions are supported.
	// An error inside the TPM response stream is parsed at this layer.
	Dispatch(command, response interface{}, sessions ...Session) error
}
