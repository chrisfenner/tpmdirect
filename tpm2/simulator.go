package tpm2

import (
	"fmt"
	"io"

	sim "github.com/chrisfenner/go-tpm-sim"
)

type Simulator struct {
	t io.ReadWriteCloser
}

func LocalSimulator() (Transport, error) {
	config := sim.TcpConfig{
		Address:      "127.0.0.1",
		TPMPort:      2321,
		PlatformPort: 2322,
	}
	tpm, err := sim.OpenTcpTpm(config)
	if err != nil {
		return nil, err
	}
	return &Simulator{
		t: tpm,
	}, nil
}

func (s *Simulator) Send(command []byte) ([]byte, error) {
	n, err := s.t.Write(command)
	if err != nil {
		return nil, err
	} else if n != len(command) {
		return nil, fmt.Errorf("partial TPM write: only %d of %d bytes", n, len(command))
	}
	rsp := make([]byte, 4096)
	n, err = s.t.Read(rsp)
	// An io.EOF after reading some data is OK.
	// Any other type of error after reading some data, or io.EOF after reading no data, is an error.
	if err != nil && !(n > 0 && err == io.EOF) {
		return nil, err
	}
	return rsp[:n], nil
}

func (s *Simulator) Close() error {
	return s.t.Close()
}
