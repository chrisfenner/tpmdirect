package tpmdirect

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestMarshalNumeric(t *testing.T) {
	vals := map[interface{}][]byte{
		true:      []byte{1},
		int8(1):   []byte{1},
		uint8(1):  []byte{1},
		int16(1):  []byte{0, 1},
		uint16(1): []byte{0, 1},
		int32(1):  []byte{0, 0, 0, 1},
		uint32(1): []byte{0, 0, 0, 1},
		int64(1):  []byte{0, 0, 0, 0, 0, 0, 0, 1},
		uint64(1): []byte{0, 0, 0, 0, 0, 0, 0, 1},
	}
	for v, want := range vals {
		t.Run(fmt.Sprintf("%v-%v", reflect.TypeOf(v), v), func(t *testing.T) {
			var buf bytes.Buffer
			marshal(&buf, reflect.ValueOf(v))
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("want %x got %x", want, buf.Bytes())
			}
		})
	}
}
