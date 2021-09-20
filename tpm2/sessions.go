package tpm2

import "fmt"

type PWSession struct {
	auth []byte
}

// PasswordSession creates a password session with the given auth value.
func PasswordSession(auth []byte) *PWSession {
	return &PWSession{
		auth: auth,
	}
}

// NonceTPM normally returns the last nonceTPM value from the session.
// Since a password session is a pseudo-session with the auth value stuffed
// in where the HMAC should go, this is not used.
func (s *PWSession) NonceTPM() []byte { return nil }

// Computes the authorization structure for the session.
func (s *PWSession) Authorize(cc TPMCC, parms, decrypt, encrypt []byte, names []TPM2BName) (*TPMSAuthCommand, error) {
	return &TPMSAuthCommand{
		Handle:     TPMRSPW,
		Nonce:      TPM2BData{},
		Attributes: TPMASession{},
		Authorization: TPM2BData{
			Buffer: s.auth,
		},
	}, nil
}

// Validates the response session structure for the session.
func (s *PWSession) Validate(rc TPMRC, cc TPMCC, parms []byte, auth *TPMSAuthResponse) error {
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
func (s *PWSession) IsEncryption() bool { return false }

// IsDecryption returns true if this is a decryption session.
// Password sessions can't be used for decryption.
func (s *PWSession) IsDecryption() bool { return false }

// If this session is used for parameter decryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for decryption.
func (s *PWSession) Encrypt(parameter []byte) error { return nil }

// If this session is used for parameter encryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for encryption.
func (s *PWSession) Decrypt(parameter []byte) error { return nil }
