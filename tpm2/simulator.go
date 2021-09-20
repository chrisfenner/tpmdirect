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
	config := sim.TcpConfig{"127.0.0.1:2321"}
	tpm, err := sim.OpenTcpTpm(&config)
	if err != nil {
		return nil, err
	}
	return &Simulator{
		t: tpm,
	}, nil
}

func (s *Simulator) Send(command []byte) ([]byte, error) {
	if n, err := s.t.Write(command); err != nil {
		return nil, err
	} else if n != len(command) {
		return nil, fmt.Errorf("partial TPM write: only %d of %d bytes", n, len(command))
	}
	rsp := make([]byte, 4096)
	n, err := s.t.Read(rsp)
	if err != nil {
		return nil, err
	}
	return rsp[:n], nil
}

func (s *Simulator) Close() error {
	return s.t.Close()
}
