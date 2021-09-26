// package tpmdirect is the reflection-based implementation of TPMDirect
package tpmdirect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/chrisfenner/tpmdirect/tpm2"
)

const (
	// Chosen based on MAX_DIGEST_BUFFER, the length of the longest reasonable
	// list returned by the reference implementation.
	maxListLength uint32 = 1024
)

// TPM represents a logical connection to a TPM. Support for
// various commands is provided at runtime using reflection.
type TPM struct {
	transport tpm2.Transport
}

// Open opens a TPM connection using the provided transport open function.
// When this TPM connection is closed, the transport is closed.
func Open(opener func() (tpm2.Transport, error)) (tpm2.Interface, error) {
	t, err := opener()
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: t,
	}, nil
}

// Close closes the connection to the TPM and its underlying
// transport.
func (t *TPM) Close() error {
	return t.transport.Close()
}

// Execute sends the provided command and returns the provided response.
func (t *TPM) Execute(cmd tpm2.Command, rsp tpm2.Response, sess ...tpm2.Session) error {
	cc := cmd.Command()
	if rsp.Response() != cc {
		panic(fmt.Sprintf("cmd and rsp must be for same command: %v != %v", cc, rsp.Response()))
	}
	hasSessions := len(sess) > 0
	wantSessions := numAuthHandles(cmd)
	if len(sess) < wantSessions {
		return fmt.Errorf("not enough sessions: command '%v' needs %d or more authorization sessions",
			reflect.TypeOf(cmd), wantSessions)
	}
	if len(sess) > 3 {
		return fmt.Errorf("too many sessions: %v", len(sess))
	}
	// Initialize the sessions, if needed
	for i, s := range sess {
		if err := s.Init(t); err != nil {
			return fmt.Errorf("initializing session %d: %w", i, err)
		}
		if err := s.NewNonceCaller(); err != nil {
			return err
		}
	}
	handles := cmdHandles(cmd)
	parms, err := cmdParameters(cmd, sess)
	if err != nil {
		return err
	}
	sessions, err := cmdSessions(t, sess, cc, parms)
	if err != nil {
		return err
	}
	hdr := cmdHeader(hasSessions, 10 /* size of command header */ +len(handles)+len(sessions)+len(parms), cc)
	command := append(hdr, handles...)
	command = append(command, sessions...)
	command = append(command, parms...)

	// Send the command via the transport.
	response, err := t.transport.Send(command)
	if err != nil {
		return err
	}

	// Parse the command directly into the response structure.
	rspBuf := bytes.NewBuffer(response)
	err = rspHeader(rspBuf)
	if err != nil {
		var bonusErrs []string
		// Emergency cleanup, then return.
		for _, s := range sess {
			if err := s.CleanupFailure(t); err != nil {
				bonusErrs = append(bonusErrs, err.Error())
			}
		}
		if len(bonusErrs) != 0 {
			return fmt.Errorf("%w - additional errors encountered during cleanup: %v", err, strings.Join(bonusErrs, ", "))
		}
		return err
	}
	err = rspHandles(rspBuf, rsp)
	if err != nil {
		return err
	}
	rspParms, err := rspParametersArea(hasSessions, rspBuf)
	if err != nil {
		return err
	}
	if hasSessions {
		// We don't need the TPM RC here because we would have errored out from rspHeader
		// TODO: Authenticate the error code with sessions, if desired.
		err = rspSessions(rspBuf, tpm2.TPMRCSuccess, cc, rspParms, sess)
		if err != nil {
			return err
		}
	}
	err = rspParameters(rspParms, sess, rsp)
	if err != nil {
		return err
	}

	return nil
}

// marshal will serialize the given values, appending them onto the given buffer.
// Panics if any of the values are not marshallable.
func marshal(buf *bytes.Buffer, vs ...reflect.Value) {
	for _, v := range vs {
		switch v.Kind() {
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			marshalNumeric(buf, v)
		case reflect.Array, reflect.Slice:
			marshalArray(buf, v)
		case reflect.Struct:
			marshalStruct(buf, v)
		default:
			panic(fmt.Sprintf("not marshallable: %#v", v))
		}
	}
}

func marshalNumeric(buf *bytes.Buffer, v reflect.Value) {
	if err := binary.Write(buf, binary.BigEndian, v.Interface()); err != nil {
		panic(err)
	}
}

func marshalArray(buf *bytes.Buffer, v reflect.Value) {
	// binary.Write knows how to marshal slices of fixed-sized values, but not dynamic-sized values
	// Iterate the contents and binary.Write them one at a time.
	for i := 0; i < v.Len(); i++ {
		if err := binary.Write(buf, binary.BigEndian, v.Index(i).Interface()); err != nil {
			panic(fmt.Sprintf("marshalling element %d of %v: %v", i, v.Type(), err))
		}
	}
}

// Marshals the members of the struct, handling sized and bitwise fields.
// May panic in the following situations:
// The struct contains a mixture of bitwise- and non-bitwise-defined fields.
// A field in the structure indicates a non-existent (or non-numeric, <MaxInt64-valued) struct field as a tag
// A field in the structure is both bitwise and a tagged union
// A field in the structure is both bitwise and sized
// A field in the structure is a tagged union that fails to marshal (see marshalUnion below)
// A field in the structure has the "list" tag but is not a slice or array type
func marshalStruct(buf *bytes.Buffer, v reflect.Value) {
	// Check if this is a bitwise-defined structure. This requires all the members to be bitwise-defined.
	if v.NumField() > 0 {
		bitwise := hasTag(v.Type().Field(0), "bit")
		for i := 0; i < v.NumField(); i++ {
			thisBitwise := hasTag(v.Type().Field(i), "bit")
			if thisBitwise {
				if hasTag(v.Type().Field(i), "sized") {
					panic(fmt.Sprintf("struct '%v' field '%v' is both bitwise and sized",
						v.Type().Name(), v.Type().Field(i).Name))
				}
				if hasTag(v.Type().Field(i), "tag") {
					panic(fmt.Sprintf("struct '%v' field '%v' is both bitwise and a tagged union",
						v.Type().Name(), v.Type().Field(i).Name))
				}
			}
			if bitwise != thisBitwise {
				panic(fmt.Sprintf("struct '%v' has mixture of bitwise and non-bitwise members", v.Type().Name()))
			}
		}
		if bitwise {
			marshalBitwise(buf, v)
			return
		}
	}
	// Make a pass to create a map of tag values
	// UInt64-valued fields with values greater than MaxInt64 cannot be selectors.
	possibleSelectors := make(map[string]int64)
	for i := 0; i < v.NumField(); i++ {
		// Special case: Treat a zero-valued nullable field as TPMAlgNull for union selection.
		// This allows callers to omit uninteresting scheme structures.
		if v.Field(i).IsZero() && hasTag(v.Type().Field(i), "nullable") {
			possibleSelectors[v.Type().Field(i).Name] = int64(tpm2.TPMAlgNull)
			continue
		}
		switch v.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			possibleSelectors[v.Type().Field(i).Name] = v.Field(i).Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			val := v.Field(i).Uint()
			if val <= math.MaxInt64 {
				possibleSelectors[v.Type().Field(i).Name] = int64(val)
			}
		}
	}
	for i := 0; i < v.NumField(); i++ {
		if hasTag(v.Type().Field(i), "skip") {
			continue
		}
		list := hasTag(v.Type().Field(i), "list")
		sized := hasTag(v.Type().Field(i), "sized")
		tag := tags(v.Type().Field(i))["tag"]
		// Serialize to a temporary buffer, in case we need to size it
		// (Better to simplify this complex reflection-based marshalling code than to save
		// some unnecessary copying before talking to a low-speed device like a TPM)
		var res bytes.Buffer
		if list {
			binary.Write(&res, binary.BigEndian, uint32(v.Field(i).Len()))
		}
		if tag != "" {
			// Check that the tagged value was present (and numeric and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			if !ok {
				panic(fmt.Sprintf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of int64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name()))
			}
			marshalUnion(&res, v.Field(i), tagValue)
		} else if v.Field(i).IsZero() && v.Field(i).Kind() == reflect.Uint32 && hasTag(v.Type().Field(i), "nullable") {
			// Special case: Anything with the same underlying type as TPMHandle's zero value is TPM_RH_NULL.
			// This allows callers to omit uninteresting handles instead of specifying them as TPM_RH_NULL.
			binary.Write(&res, binary.BigEndian, uint32(tpm2.TPMRHNull))
		} else if v.Field(i).IsZero() && v.Field(i).Kind() == reflect.Uint16 && hasTag(v.Type().Field(i), "nullable") {
			// Special case: Anything with the same underlying type as TPMAlg's zero value is TPM_ALG_NULL.
			// This allows callers to omit uninteresting algorithms/schemes instead of specifying them as TPM_ALG_NULL.
			binary.Write(&res, binary.BigEndian, uint16(tpm2.TPMAlgNull))
		} else {
			marshal(&res, v.Field(i))
		}
		if sized {
			binary.Write(buf, binary.BigEndian, uint16(res.Len()))
		}
		buf.Write(res.Bytes())
	}
}

// Marshals a bitwise-defined struct.
// May panic in the following situations:
// Not all bits are assigned to a field
// The highest bit index is not a multiple of 8, minus 1
// A field has a range-based selector that is not highest-bit first
// The bits assigned to a field are more than the size of the field's type
// Members of a field are anything other than Uint type values
func marshalBitwise(buf *bytes.Buffer, v reflect.Value) {
	maxBit := 0
	for i := 0; i < v.NumField(); i++ {
		high, _, ok := rangeTag(v.Type().Field(i), "bit")
		if !ok {
			panic(fmt.Sprintf("'%v' struct member '%v' did not specify a bit index or range", v.Type().Name(), v.Type().Field(i).Name))
		}
		if high > maxBit {
			maxBit = high
		}
	}
	if (maxBit+1)%8 != 0 {
		panic(fmt.Sprintf("'%v' bitwise members did not total up to a multiple of 8 bits", v.Type().Name()))
	}
	bitArray := make([]bool, maxBit+1)
	for i := 0; i < v.NumField(); i++ {
		high, low, _ := rangeTag(v.Type().Field(i), "bit")
		var buf bytes.Buffer
		marshal(&buf, v.Field(i))
		b := buf.Bytes()
		for i := 0; i <= (high - low); i++ {
			bitArray[low+i] = ((b[len(b)-i/8-1] >> (i % 8)) & 1) == 1
		}
	}
	result := make([]byte, len(bitArray)/8)
	for i, bit := range bitArray {
		if bit {
			result[len(result)-(i/8)-1] |= (1 << (i % 8))
		}
	}
	buf.Write(result)
}

// Marshals the member of the given union struct corresponding to the given selector.
// Marshals nothing if the selector is equal to TPM_ALG_NULL (0x0010)
// May panic in the following situations:
// The passed-in value is not a union struct (i.e., a structure of all pointer members with selector tags)
// The passed-in selector value is not handled in any case in the union
// The selected value in the passed-in struct is nil
func marshalUnion(buf *bytes.Buffer, v reflect.Value, selector int64) {
	// Special case: TPM_ALG_NULL as a selector means marshal nothing
	if selector == int64(tpm2.TPMAlgNull) {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		sel, ok := numericTag(v.Type().Field(i), "selector")
		if !ok {
			panic(fmt.Sprintf("'%v' union member '%v' did not have a selector tag", v.Type().Name(), v.Type().Field(i).Name))
		}
		if sel == selector {
			if v.Field(i).IsNil() {
				// Special case: if the selected value is found but nil, marshal the zero-value instead
				marshal(buf, reflect.New(v.Field(i).Type().Elem()).Elem())
			} else {
				marshal(buf, v.Field(i).Elem())
			}
			return
		}
	}
	panic(fmt.Sprintf("selector value '%v' not handled for type '%v'", selector, v.Type().Name()))
}

// unmarshal will deserialize the given values from the given buffer.
// Returns an error if the buffer does not contain enough data to satisfy the type.
// panics if a non-settable value is passed, or the values are not marshallable types.
func unmarshal(buf *bytes.Buffer, vs ...reflect.Value) error {
	for _, v := range vs {
		switch v.Kind() {
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return unmarshalNumeric(buf, v)
		case reflect.Slice:
			var length uint32
			// special case for byte slices: just read the entire rest of the buffer
			if v.Type().Elem().Kind() == reflect.Uint8 {
				length = uint32(buf.Len())
			} else {
				err := unmarshalNumeric(buf, reflect.ValueOf(&length).Elem())
				if err != nil {
					return fmt.Errorf("deserializing size for field of type '%v': %w", v.Type(), err)
				}
			}
			if length > uint32(math.MaxInt32) || length > maxListLength {
				return fmt.Errorf("could not deserialize slice of length %v", length)
			}
			// Go's reflect library doesn't allow increasing the capacity of an existing slice.
			// Since we can't be sure that the capacity of the passed-in value was enough, allocate
			// a new temporary one of the correct length, unmarshal to it, and swap it in.
			tmp := reflect.MakeSlice(v.Type(), int(length), int(length))
			if err := unmarshalArray(buf, tmp); err != nil {
				return err
			}
			v.Set(tmp)
			continue
		case reflect.Array:
			if err := unmarshalArray(buf, v); err != nil {
				return err
			}
			continue
		case reflect.Struct:
			if err := unmarshalStruct(buf, v); err != nil {
				return err
			}
			continue
		default:
			panic(fmt.Sprintf("not unmarshallable: %v", v.Type()))
		}
	}
	return nil
}

func unmarshalNumeric(buf *bytes.Buffer, v reflect.Value) error {
	return binary.Read(buf, binary.BigEndian, v.Addr().Interface())
}

// For slices, the slice's length must already be set to the expected amount of data.
func unmarshalArray(buf *bytes.Buffer, v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		if err := unmarshal(buf, v.Index(i)); err != nil {
			return fmt.Errorf("deserializing slice/array index %v: %w", i, err)
		}
	}
	return nil
}

func unmarshalStruct(buf *bytes.Buffer, v reflect.Value) error {
	// Check if this is a bitwise-defined structure. This requires all the members to be bitwise-defined.
	if v.NumField() > 0 {
		bitwise := hasTag(v.Type().Field(0), "bit")
		for i := 0; i < v.NumField(); i++ {
			thisBitwise := hasTag(v.Type().Field(i), "bit")
			if thisBitwise {
				if hasTag(v.Type().Field(i), "sized") {
					panic(fmt.Sprintf("struct '%v' field '%v' is both bitwise and sized",
						v.Type().Name(), v.Type().Field(i).Name))
				}
				if hasTag(v.Type().Field(i), "tag") {
					panic(fmt.Sprintf("struct '%v' field '%v' is both bitwise and a tagged union",
						v.Type().Name(), v.Type().Field(i).Name))
				}
			}
			if bitwise != thisBitwise {
				panic(fmt.Sprintf("struct '%v' has mixture of bitwise and non-bitwise members", v.Type().Name()))
			}
		}
		if bitwise {
			return unmarshalBitwise(buf, v)
		}
	}
	for i := 0; i < v.NumField(); i++ {
		if hasTag(v.Type().Field(i), "skip") {
			continue
		}
		list := hasTag(v.Type().Field(i), "list")
		if list && (v.Field(i).Kind() != reflect.Slice) {
			panic(fmt.Sprintf("field '%v' of struct '%v' had the 'list' tag but was not a slice",
				v.Type().Field(i).Name, v.Type().Name()))
		}
		// Slices of anything but byte/uint8 must have the 'list' tag.
		if !list && (v.Field(i).Kind() == reflect.Slice) && (v.Type().Field(i).Type.Elem().Kind() != reflect.Uint8) {
			panic(fmt.Sprintf("field '%v' of struct '%v' was a slice of non-byte but did not have the 'list' tag",
				v.Type().Field(i).Name, v.Type().Name()))
		}
		sized := hasTag(v.Type().Field(i), "sized")
		var expectedSize uint16
		// If sized, unmarshal a size field first, then restrict unmarshalling to the given size
		bufToReadFrom := buf
		if sized {
			binary.Read(buf, binary.BigEndian, &expectedSize)
			sizedBufArray := make([]byte, int(expectedSize))
			n, err := buf.Read(sizedBufArray)
			if n != int(expectedSize) {
				return fmt.Errorf("ran out of data reading sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			if err != nil {
				return fmt.Errorf("error reading data for parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
			bufToReadFrom = bytes.NewBuffer(sizedBufArray)
		}
		tag := tags(v.Type().Field(i))["tag"]
		if tag != "" {
			// Make a pass to create a map of tag values
			// UInt64-valued fields with values greater than MaxInt64 cannot be selectors.
			possibleSelectors := make(map[string]int64)
			for j := 0; j < v.NumField(); j++ {
				switch v.Field(j).Kind() {
				case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					possibleSelectors[v.Type().Field(j).Name] = v.Field(j).Int()
				case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					val := v.Field(j).Uint()
					if val <= math.MaxInt64 {
						possibleSelectors[v.Type().Field(j).Name] = int64(val)
					}
				}
			}
			// Check that the tagged value was present (and numeric and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			if !ok {
				panic(fmt.Sprintf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of in64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name()))
			}
			if err := unmarshalUnion(bufToReadFrom, v.Field(i), tagValue); err != nil {
				return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
			}
		} else {
			if err := unmarshal(bufToReadFrom, v.Field(i)); err != nil {
				return fmt.Errorf("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
			}
		}
		if sized {
			if bufToReadFrom.Len() != 0 {
				return fmt.Errorf("extra data at the end of sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
		}
	}
	return nil
}

// Unmarshals a bitwise-defined struct.
// May panic in the following situations:
// Not all bits are assigned to a field
// The highest bit index is not a multiple of 8, minus 1
// A field has a range-based selector that is not highest-bit first
// The bits assigned to a field are more than the size of the field's type
// Members of a field are anything other than Uint or bool type values
func unmarshalBitwise(buf *bytes.Buffer, v reflect.Value) error {
	maxBit := 0
	for i := 0; i < v.NumField(); i++ {
		high, _, ok := rangeTag(v.Type().Field(i), "bit")
		if !ok {
			panic(fmt.Sprintf("'%v' struct member '%v' did not specify a bit index or range", v.Type().Name(), v.Type().Field(i).Name))
		}
		if high > maxBit {
			maxBit = high
		}
	}
	if (maxBit+1)%8 != 0 {
		panic(fmt.Sprintf("'%v' bitwise members did not total up to a multiple of 8 bits", v.Type().Name()))
	}
	bitArray := make([]bool, maxBit+1)
	// We will read big-endian, starting from the last byte and working our way down.
	for i := len(bitArray)/8 - 1; i >= 0; i-- {
		b, err := buf.ReadByte()
		if err != nil {
			return fmt.Errorf("error %d bits into field '%v' of struct '%v': %w",
				i, v.Type().Field(i).Name, v.Type().Name(), err)
		}
		for j := 0; j < 8; j++ {
			bitArray[8*i+j] = (((b >> j) & 1) == 1)
		}
	}
	for i := 0; i < v.NumField(); i++ {
		high, low, _ := rangeTag(v.Type().Field(i), "bit")
		var val uint64
		for j := 0; j <= high-low; j++ {
			if bitArray[low+j] {
				val |= (1 << j)
			}
		}
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool((val & 1) == 1)
		} else {
			v.Field(i).SetUint(val)
		}
	}
	return nil
}

// Unmarshals the member of the given union struct corresponding to the given selector.
// Unmarshals nothing if the selector is TPM_ALG_NULL (0x0010)
// May panic in the following situations:
// The passed-in value is not a union struct (i.e., a structure of all pointer members with selector tags)
// The passed-in selector value is not handled in any case in the union
// The selected value in the passed-in struct is nil
func unmarshalUnion(buf *bytes.Buffer, v reflect.Value, selector int64) error {
	// Special case: TPM_ALG_NULL as a selector means unmarshal nothing
	if selector == int64(tpm2.TPMAlgNull) {
		return nil
	}
	for i := 0; i < v.NumField(); i++ {
		sel, ok := numericTag(v.Type().Field(i), "selector")
		if !ok {
			panic(fmt.Sprintf("'%v' union member '%v' did not have a selector tag", v.Type().Name(), v.Type().Field(i).Name))
		}
		if sel == selector {
			val := reflect.New(v.Type().Field(i).Type.Elem())
			if err := unmarshal(buf, val.Elem()); err != nil {
				return fmt.Errorf("unmarshalling '%v' union member '%v': %w", v.Type().Name(), v.Type().Field(i).Name, err)
			}
			v.Field(i).Set(val)
			return nil
		}
	}
	panic(fmt.Sprintf("selector value '%v' not handled for type '%v'", selector, v.Type().Name()))
}

// Returns all the tpmdirect tags on a field as a map.
// Some tags are settable (with "="). For these, the value is the RHS.
// For all others, the value is the empty string.
func tags(t reflect.StructField) map[string]string {
	allTags, ok := t.Tag.Lookup("tpmdirect")
	if !ok {
		return nil
	}
	result := make(map[string]string)
	tags := strings.Split(allTags, ",")
	for _, tag := range tags {
		// Split on the equals sign for settable tags.
		// If the split returns an empty slice, this is an empty tag.
		// If the split returns a slice of length 1, this is an un-settable tag.
		// If the split returns a slice of length 2, this is a settable tag.
		assignment := strings.SplitN(tag, "=", 2)
		val := ""
		if len(assignment) > 1 {
			val = assignment[1]
		}
		if len(assignment) > 0 {
			key := assignment[0]
			result[key] = val
		}
	}
	return result
}

// hasTag looks up to see if the type's tpmdirect-namespaced tag contains the given value.
// Returns false if there is no tpmdirect-namespaced tag on the type.
func hasTag(t reflect.StructField, tag string) bool {
	ts := tags(t)
	_, ok := ts[tag]
	return ok
}

// Returns the numeric tag value, or false if the tag is not present.
// Panics if the value is found, but not numeric.
func numericTag(t reflect.StructField, tag string) (int64, bool) {
	val, ok := tags(t)[tag]
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(val, 0, 64)
	if err != nil {
		panic(fmt.Sprintf("expected numeric int64 tag value for '%v', got '%v', tag, val", tag, val))
	}
	return v, true
}

// Returns the range on a tag like 4:3 or 4.
// If there is no colon, the low and high part of the range are equal.
// Panics if the first value is not greater than the second value, or there is more than one colon
func rangeTag(t reflect.StructField, tag string) (int, int, bool) {
	val, ok := tags(t)[tag]
	if !ok {
		return 0, 0, false
	}
	vals := strings.Split(val, ":")
	if len(vals) > 2 {
		panic(fmt.Sprintf("tag value '%v' contained too many colons", val))
	}
	high, err := strconv.Atoi(vals[0])
	if err != nil {
		panic(fmt.Sprintf("tag value '%v' contained non-numeric range value", val))
	}
	low := high
	if len(vals) > 1 {
		low, err = strconv.Atoi(vals[1])
		if err != nil {
			panic(fmt.Sprintf("tag value '%v' contained non-numeric range value", val))
		}
	}
	if low > high {
		panic(fmt.Sprintf("tag value '%v' specified range in order low-to-high", val))
	}
	return high, low, true
}

// taggedMembers will return a slice of all the members of the given
// structure that contain (or don't contain) the given tag in the "tpmdirect"
// namespace.
// Panics if v's Kind is not Struct.
func taggedMembers(v reflect.Value, tag string, invert bool) []reflect.Value {
	var result []reflect.Value
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		// Add this one to the list if it has the tag and we're not inverting,
		// or if it doesn't have the tag and we are inverting.
		if hasTag(t.Field(i), tag) != invert {
			result = append(result, v.Field(i))
		}
	}

	return result
}

// numAuthHandles returns the number of authorization sessions needed for the command.
func numAuthHandles(cmd tpm2.Command) int {
	result := 0
	cmdType := reflect.TypeOf(cmd).Elem()
	for i := 0; i < cmdType.NumField(); i++ {
		if hasTag(cmdType.Field(i), "auth") {
			result++
		}
	}
	return result
}

// cmdHandles returns the handles area of the command.
func cmdHandles(cmd tpm2.Command) []byte {
	handles := taggedMembers(reflect.ValueOf(cmd).Elem(), "handle", false)

	// Initial capacity is enough to hold 3 handles
	result := bytes.NewBuffer(make([]byte, 0, 12))

	marshal(result, handles...)

	return result.Bytes()
}

// cmdParameters returns the parameters area of the command.
// The first parameter may be encrypted by one of the sessions.
func cmdParameters(cmd tpm2.Command, sess []tpm2.Session) ([]byte, error) {
	parms := taggedMembers(reflect.ValueOf(cmd).Elem(), "handle", true)
	if len(parms) == 0 {
		return nil, nil
	}

	// Marshal the first parameter for in-place session encryption.
	var firstParm bytes.Buffer
	marshal(&firstParm, parms[0])
	firstParmBytes := firstParm.Bytes()

	// Encrypt the first parameter if there are any decryption sessions.
	encrypted := false
	for i, s := range sess {
		if s.IsDecryption() {
			if encrypted {
				// Only one session may be used for decryption.
				return nil, fmt.Errorf("too many decrypt sessions")
			}
			if len(firstParmBytes) < 2 {
				return nil, fmt.Errorf("this command's first parameter is not a TPM2B")
			}
			err := s.Encrypt(firstParmBytes[2:])
			if err != nil {
				return nil, fmt.Errorf("encrypting with session %d: %w", i, err)
			}
			encrypted = true
		}
	}

	var result bytes.Buffer
	result.Write(firstParmBytes)
	// Write the rest of the parameters normally.
	marshal(&result, parms[1:]...)
	return result.Bytes(), nil
}

// cmdSessions returns the authorization area of the command.
func cmdSessions(tpm *TPM, sess []tpm2.Session, cc tpm2.TPMCC, parms []byte) ([]byte, error) {
	// There is no authorization area if there are no sessions.
	if len(sess) == 0 {
		return nil, nil
	}
	// Find the non-first-session encryption and decryption session nonceTPMs, if any.
	var encNonceTPM, decNonceTPM []byte
	if len(sess) > 0 {
		for i := 1; i < len(sess); i++ {
			s := sess[i]
			if s.IsEncryption() {
				if encNonceTPM != nil {
					// Only one encrypt session is permitted.
					return nil, fmt.Errorf("too many encrypt sessions")
				}
				encNonceTPM = s.NonceTPM()
				// A session used for both encryption and decryption only
				// needs its nonce counted once.
				continue
			}
			if s.IsDecryption() {
				if decNonceTPM != nil {
					// Only one decrypt session is permitted.
					return nil, fmt.Errorf("too many decrypt sessions")
				}
				decNonceTPM = s.NonceTPM()
			}
		}
	}
	// Find all the names being authorized by this command.
	var names []byte
	for _, s := range sess {
		names = append(names, s.AuthorizedName()...)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	// Skip space to write the size later
	buf.Write(make([]byte, 4))
	// Calculate the authorization HMAC for each session
	for i, s := range sess {
		var addNonces []byte
		// Special case: the HMAC on the first authorization session of a command
		// also includes any decryption and encryption nonceTPMs, too.
		if i == 0 {
			addNonces = append(addNonces, decNonceTPM...)
			addNonces = append(addNonces, encNonceTPM...)
		}
		auth, err := s.Authorize(cc, parms, addNonces, names)
		if err != nil {
			return nil, fmt.Errorf("session %d: %w", i, err)
		}
		marshal(buf, reflect.ValueOf(auth).Elem())
	}

	result := buf.Bytes()
	// Write the size
	binary.BigEndian.PutUint32(result[0:], uint32(buf.Len()-4))

	return result, nil
}

// cmdHeader returns the structured TPM command header.
func cmdHeader(hasSessions bool, length int, cc tpm2.TPMCC) []byte {
	tag := tpm2.TPMSTNoSessions
	if hasSessions {
		tag = tpm2.TPMSTSessions
	}
	hdr := tpm2.TPMCmdHeader{
		Tag:         tag,
		Length:      uint32(length),
		CommandCode: cc,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 8))
	marshal(buf, reflect.ValueOf(hdr))
	return buf.Bytes()
}

// rspHeader parses the response header. If the TPM returned an error,
// returns an error here.
// rsp is updated to point to the rest of the response after the header.
func rspHeader(rsp *bytes.Buffer) error {
	var hdr tpm2.TPMRspHeader
	if err := unmarshal(rsp, reflect.ValueOf(&hdr).Elem()); err != nil {
		return fmt.Errorf("unmarshalling TPM response: %w", err)
	}
	if hdr.ResponseCode != tpm2.TPMRCSuccess {
		return hdr.ResponseCode
	}
	return nil
}

// rspHandles parses the response handles area into the response structure.
// If there is a mismatch between the expected and actual amount of handles,
// returns an error here.
// rsp is updated to point to the rest of the response after the handles.
func rspHandles(rsp *bytes.Buffer, rspStruct tpm2.Response) error {
	handles := taggedMembers(reflect.ValueOf(rspStruct).Elem(), "handle", false)
	for i, handle := range handles {
		if err := unmarshal(rsp, handle); err != nil {
			return fmt.Errorf("unmarshalling handle %v: %w", i, err)
		}
	}
	return nil
}

// rspParametersArea fetches, but does not manipulate, the parameters area
// from the command. If there is a mismatch between the response's
// indicated parameters area size and the actual size, returns an error here.
// rsp is updated to point to the rest of the response after the handles.
func rspParametersArea(hasSessions bool, rsp *bytes.Buffer) ([]byte, error) {
	var length uint32
	if hasSessions {
		if err := binary.Read(rsp, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("reading length of parameter area: %w", err)
		}
	} else {
		// If there are no sessions, there is no length-of-parameters field,
		// because the whole rest of the response is the parameters area.
		length = uint32(rsp.Len())
	}
	if length > uint32(rsp.Len()) {
		return nil, fmt.Errorf("response indicated %d bytes of parameters but there "+
			"were only %d more bytes of response", length, rsp.Len())
	}
	if length > math.MaxInt32 {
		return nil, fmt.Errorf("invalid length of parameter area: %d", length)
	}
	parms := make([]byte, int(length))
	if n, err := rsp.Read(parms); err != nil {
		return nil, fmt.Errorf("reading parameter area: %w", err)
	} else if n != len(parms) {
		return nil, fmt.Errorf("only read %d bytes of parameters, expected %d", n, len(parms))
	}
	return parms, nil
}

// rspSessions fetches the sessions area of the response and updates all
// the sessions with it. If there is a response validation error, returns
// an error here.
// rsp is updated to point to the rest of the response after the sessions.
func rspSessions(rsp *bytes.Buffer, rc tpm2.TPMRC, cc tpm2.TPMCC, parms []byte, sess []tpm2.Session) error {
	for i, s := range sess {
		var auth tpm2.TPMSAuthResponse
		if err := unmarshal(rsp, reflect.ValueOf(&auth).Elem()); err != nil {
			return fmt.Errorf("reading auth session %d: %w", i, err)
		}
		if err := s.Validate(rc, cc, parms, &auth); err != nil {
			return fmt.Errorf("validating auth session %d: %w", i, err)
		}
	}
	if rsp.Len() != 0 {
		return fmt.Errorf("%d unaccounted-for bytes at the end of the TPM response", rsp.Len())
	}
	return nil
}

// rspParameters decrypts (if needed) the parameters area of the response
// into the response structure. If there is a mismatch between the expected
// and actual response structure, returns an error here.
func rspParameters(parms []byte, sess []tpm2.Session, rspStruct tpm2.Response) error {
	parmsFields := taggedMembers(reflect.ValueOf(rspStruct).Elem(), "handle", true)

	// Use the heuristic of "does interpreting the first 2 bytes of response as a length
	// make any sense" to attempt encrypted paramter decryption.
	// If the command supports parameter encryption, the first paramter is a 2B
	if len(parms) < 2 {
		return nil
	}
	length := binary.BigEndian.Uint16(parms[0:])
	// TODO: Make this nice using structure tagging.
	if int(length)+2 > len(parms) {
		// Assume this means the command does not support parameter encryption.
		return nil
	}
	for i, s := range sess {
		if !s.IsEncryption() {
			continue
		}
		if err := s.Decrypt(parms[2 : 2+length]); err != nil {
			return fmt.Errorf("decrypting first parameter with session %d: %w", i, err)
		}
	}
	return unmarshal(bytes.NewBuffer(parms), parmsFields...)
}
