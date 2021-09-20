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
		false:              []byte{0},
		byte(1):            []byte{1},
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

func TestMarshalArray(t *testing.T) {
	vals := []struct {
		Data          interface{}
		Serialization []byte
	}{
		{[4]int8{1, 2, 3, 4}, []byte{1, 2, 3, 4}},
		{[3]uint16{5, 6, 7}, []byte{0, 5, 0, 6, 0, 7}},
	}
	for _, val := range vals {
		v, want := val.Data, val.Serialization
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

func TestMarshalSlice(t *testing.T) {
	// Slices in reflect/tpmdirect must be tagged marshalled/unmarshalled as
	// part of a struct with the 'list' tag
	type sliceWrapper struct {
		Elems []uint32 `tpm2:"list"`
	}
	vals := []struct {
		Name          string
		Data          sliceWrapper
		Serialization []byte
	}{
		{"3", sliceWrapper{[]uint32{1, 2, 3}}, []byte{0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3}},
		{"1", sliceWrapper{[]uint32{4}}, []byte{0, 0, 0, 1, 0, 0, 0, 4}},
		{"empty", sliceWrapper{[]uint32{}}, []byte{0, 0, 0, 0}},
	}
	for _, val := range vals {
		v, want := val.Data, val.Serialization
		t.Run(val.Name, func(t *testing.T) {
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
