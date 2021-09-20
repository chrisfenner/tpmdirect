package tpmdirect

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMarshalNumeric(t *testing.T) {
	vals := map[interface{}][]byte{
		true:               []byte{1},
		int8(2):            []byte{2},
		uint8(3):           []byte{3},
		int16(260):         []byte{1, 4},
		uint16(261):        []byte{1, 5},
		int32(65542):       []byte{0, 1, 0, 6},
		uint32(65543):      []byte{0, 1, 0, 7},
		int64(4294967304):  []byte{0, 0, 0, 1, 0, 0, 0, 8},
		uint64(4294967305): []byte{0, 0, 0, 1, 0, 0, 0, 9},
	}
	for v, want := range vals {
		t.Run(fmt.Sprintf("%v-%v", reflect.TypeOf(v), v), func(t *testing.T) {
			var buf bytes.Buffer
			marshal(&buf, reflect.ValueOf(v))
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("want %x got %x", want, buf.Bytes())
			}
			got := reflect.New(reflect.TypeOf(v))
			err := unmarshal(&buf, got.Elem())
			if err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if !cmp.Equal(v, got.Elem().Interface()) {
				t.Errorf("want %#v, got %#v\n%v", v, got.Elem().Interface(), cmp.Diff(v, got.Elem().Interface()))
			}
		})
	}
}
