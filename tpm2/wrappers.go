package tpm2

// Provide wrapper functions for concrete types used by tpm2, for setting union members.

func NewTPMKeyBits(v TPMKeyBits) *TPMKeyBits { return &v }

func NewTPMAlgID(v TPMAlgID) *TPMAlgID { return &v }
