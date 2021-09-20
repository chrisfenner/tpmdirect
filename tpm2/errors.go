package tpm2

import (
	"fmt"
)

const (
	TPMRCSuccess TPMRC = 0
)

func (r TPMRC) Error() string {
	// TODO: Formatting and other TPM error comprehension
	return fmt.Sprintf("TPM error code: %x", uint32(r))
}
