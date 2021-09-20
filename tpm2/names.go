package tpm2

import (
	"bytes"
	"encoding/binary"
)

func NamedPrimaryHandle(h TPMHandle) NamedHandle {
	var name bytes.Buffer
	binary.Write(&name, binary.BigEndian, h)
	return NamedHandle{
		Handle: h,
		Name:   name.Bytes(),
	}
}
