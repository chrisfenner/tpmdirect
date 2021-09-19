// package tpmdirect is the reflection-based implementation of TPMDirect
package tpmdirect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/chrisfenner/tpmdirect/tpm2"
)

const (
	// Chosen based on MAX_ALG_LIST_SIZE, the length of the longest reasonable
	// list returned by the reference implementation.
	maxListLength uint32 = 64
)

// TPM represents a logical connection to a TPM. Support for
// various commands is provided at runtime using reflection.
type TPM struct {
	transport tpm2.Transport
}

// OpenTPM opens a TPM connection on the provided transport.
// Takes ownership of the provided transport.
// When this TPM connection is closed, the transport is closed.
func OpenTPM(transport tpm2.Transport) {
	return TPM{
		transport: transport,
	}
}

// Close closes the connection to the TPM and its underlying
// transport.
func (t TPM) Close() error {
	return transport.Close()
}

// Execute sends the provided command and returns the provided response.
func (t TPM) Execute(cmd tpm2.Command, rsp tpm2.Response, sess ...tpm2.Session) error {
	cc := cmd.Command()
	if rsp.Response() != cc {
		panic(fmt.Sprintf("cmd and rsp must be for same command: %v != %v", cc, rsp.Response()))
	}
	hasSessions := len(sess) > 0
	if len(sess > 3) {
		panic(fmt.Sprintf("too many sessions: %v", len(sess)))
	}
	handles := cmdHandles(cmd)
	parms := cmdParameters(cmd, sess)
	sessions := cmdSessions(sess, parms)
	hdr := cmdHeader(hasSessions, len(handles)+len(sessions)+len(parms), cc)
	command := append(hdr, handles, sessions, parms)

	// Send the command via the transport.
	response, err := transport.Send(command)
	if err != nil {
		return err
	}

	// Parse the command directly into the response structure.
	err = rspHeader(&response)
	if err != nil {
		return err
	}
	err = rspHandles(&response, rsp)
	if err != nil {
		return err
	}
	rspParms, err := rspParametersArea(&response)
	if err != nil {
		return err
	}
	err = rspSessions(&response, rspParms, sess)
	if err != nil {
		return err
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
			// For lists, prepend with a uint32 containing the length.
			if hasTag(v.Type(), "list") {
				marshal(buf, reflect.ValueOf(uint32(v.Len())))
			}
			marshalArray(buf, v)
		case reflect.Struct:
			marshalStruct(buf, v)
		default:
			panic(fmt.Sprintf("not marshallable: %v", v))
		}
	}
}

func marshalNumeric(buf *bytes.Buffer, v reflect.Value) {
	if err := binary.Write(buf, binary.BigEndian, v.Interface()); err != nil {
		panic(err)
	}
}

func marshalArray(buf *bytes.Buffer, v reflect.Value) {
	if err := binary.Write(buf, binary.BigEndian, v.Interface()); err != nil {
		panic(err)
	}
}

// Marshals the members of the struct, handling sized and bitwise fields.
// May panic in the following situations:
// The struct contains a mixture of bitwise- and non-bitwise-defined fields.
// A field in the structure indicates a non-existent (or non-numeric, <MaxInt64-valued) struct field as a tag
// A field in the structure is both bitwise and a tagged union
// A field in the structure is both bitwise and sized
// A field in the structure is a tagged union that fails to marshal (see marshalUnion below)
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
		if isBitwise {
			marshalBitwise(buf, v)
			return
		}
	}
	// Make a pass to create a map of tag values
	// UInt64-valued fields with values greater than MaxInt64 cannot be selectors.
	possibleSelectors := make(map[string]int64)
	for i := 0; i < v.NumField(); i++ {
		switch v.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			possibleSelectors[v.Type().Field(i).Name()] = v.Field(i).Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			val := v.Field(i).Uint()
			if val <= math.MaxInt64 {
				possibleSelectors[v.Type().Field(i).Name()] = int64(val)
			}
		}
	}
	for i := 0; i < v.NumField(); i++ {
		sized := hasTag(v.Type().Field(i), "sized")
		tag := tags(v.Type().Field(i), "tag")
		// Serialize to a temporary buffer, in case we need to size it
		// (Better to simplify this complex reflection-based marshalling code than to save
		// some unnecessary copying before talking to a low-speed device like a TPM)
		var res bytes.Buffer
		if tag != "" {
			// Check that the tagged value was present (and numeric and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			if !ok {
				panic(fmt.Sprintf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of in64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name()))
			}
			marshalUnion(&res, v.Field(i), tagValue)
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
func marshalBitwise(buf *bytes.Buffer, v reflect.Value) {
	maxBit := 0
	for i := 0; i < v.NumField(); i++ {
		high, _, ok := rangeTag(v.Type().Field(i), "bit")
		if !ok {
			panic("'%v' struct member '%v' did not specify a bit index or range", v.Type().Name(), v.Type().Field(i).Name)
		}
		if high > maxBit {
			maxBit = high
		}
	}
	if (maxBit+1)%8 != 0 {
		panic("'%v' bitwise members did not total up to a multiple of 8 bits", v.Type().Name())
	}
	bitArray := make([]bool, maxBit+1)
	for i := 0; i < v.NumField(); i++ {
		high, low := rangeTag(v.Type().Field(i), "bit")
		var buf bytes.Buffer
		marshal(&buf, v.Field(i))
		b := buf.Bytes()
		for i := 0; i <= (high - low); i++ {
			bitArray[low+i] = ((b[i/8] >> (i % 8)) & 1) == 1
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
// May panic in the following situations:
// The passed-in value is not a union struct (i.e., a structure of all pointer members with selector tags)
// The passed-in selector value is not handled in any case in the union
// The selected value in the passed-in struct is nil
func marshalUnion(buf *bytes.Buffer, v reflect.Value, selector int64) {
	for i := 0; i < v.NumField(); i++ {
		sel, ok := numericTag(v.Type().Field(i), selector)
		if !ok {
			panic(fmt.Sprintf("'%v' union member '%v' did not have a selector tag", v.Type().Name(), v.Type().Field(i).Name))
		}
		if sel == selector {
			marshal(buf, v.Field(i).Elem())
			return
		}
	}
	panic(fmt.Sprintf("selector value '%v' not handled for type '%v'", selector.v.Type()))
}

// unmarshal will deserialize the given values from the given buffer.
// Returns an error if the buffer does not contain enough data to satisfy the type.
// panics if a non-pointer value is passed, or the values are not marshallable types.
func unmarshal(buf *bytes.Buffer, vs ...reflect.Value) error {
	for _, vptr := range vs {
		if vptr.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("non-pointer value passed to unmarshal: %v", vptr.Type()))
		}
		v := vptr.Elem()
		switch v.Kind() {
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return unmarshalNumeric(buf, v)
		case reflect.Slice:
			// For lists, expect a uint32 containing the length.
			if !hasTag(v.Type(), "list") {
				return fmt.Errorf("could not deserialize slice of type '%v' without length", v.Type())
			}
			var length uint32
			err := unmarshalNumeric(buf, reflect.ValueOf(&length))
			if err != nil {
				return fmt.Errorf("deserializing size for field of type '%v': %w", v.Type(), err)
			}
			if length > uint32(math.MaxInt) || length > maxListLength {
				return fmt.Errorf("could not deserialize slice of length %v", length)
			}
			// Go's reflect library doesn't allow increasing the capacity of an existing slice.
			// Since we can't be sure that the capacity of the passed-in value was enough, allocate
			// a new temporary one of the correct length, unmarshal to it, and swap it in.
			tmp := reflect.MakeSlice(v.Type().Elem(), length, length)
			if err := unmarshalArray(buf, tpm); err != nil {
				return err
			}
			v.Set(tmp)
			return nil
		case reflect.Array:
			return unmarshalArray(buf, v)
		case reflect.Struct:
			return unmarshalStruct(buf, v)
		default:
			panic(fmt.Sprintf("not marshallable: %v", v.Type()))
		}
	}
	return nil
}

func unmarshalNumeric(buf *bytes.Buffer, v reflect.Value) error {
	return binary.Read(buf, binary.BigEndian, v.Interface())
}

// For slices, the slice's length must already be set to the expected amount of data.
func unmarshalArray(buf *bytes.Buffer, v reflect.Value) error {
	for i := range v.Len() {
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
		if isBitwise {
			return unmarshalBitwise(buf, v)
		}
	}
	// Make a pass to create a map of tag values
	// UInt64-valued fields with values greater than MaxInt64 cannot be selectors.
	possibleSelectors := make(map[string]int64)
	for i := 0; i < v.NumField(); i++ {
		switch v.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			possibleSelectors[v.Type().Field(i).Name()] = v.Field(i).Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			val := v.Field(i).Uint()
			if val <= math.MaxInt64 {
				possibleSelectors[v.Type().Field(i).Name()] = int64(val)
			}
		}
	}
	for i := 0; i < v.NumField(); i++ {
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
		tag := tags(v.Type().Field(i), "tag")
		if tag != "" {
			// Check that the tagged value was present (and numeric and smaller than MaxInt64)
			tagValue, ok := possibleSelectors[tag]
			if !ok {
				panic(fmt.Sprintf("union tag '%v' for member '%v' of struct '%v' did not reference "+
					"a numeric field of in64-compatible value",
					tag, v.Type().Field(i).Name, v.Type().Name()))
			}
			if err := unmarshalUnion(&res, v.Field(i), tagValue); err != nil {
				return fmt.Errof("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
			}
		} else {
			if err := unmarshal(&res, v.Field(i)); err != nil {
				return fmt.Errof("unmarshalling field %v of struct of type '%v', %w", i, v.Type(), err)
			}
		}
		if sized {
			if bufToReadFrom.Len() != 0 {
				return fmt.Errorf("extra data at the end of sized parameter '%v' inside struct of type '%v'",
					v.Type().Field(i).Name, v.Type().Name())
			}
		}
	}
}

// Unmarshals a bitwise-defined struct.
// May panic in the following situations:
// Not all bits are assigned to a field
// The highest bit index is not a multiple of 8, minus 1
// A field has a range-based selector that is not highest-bit first
// The bits assigned to a field are more than the size of the field's type
func unmarshalBitwise(buf *bytes.Buffer, v reflect.Value) error {
	maxBit := 0
	for i := 0; i < v.NumField(); i++ {
		high, _, ok := rangeTag(v.Type().Field(i), "bit")
		if !ok {
			panic("'%v' struct member '%v' did not specify a bit index or range", v.Type().Name(), v.Type().Field(i).Name)
		}
		if high > maxBit {
			maxBit = high
		}
	}
	if (maxBit+1)%8 != 0 {
		panic("'%v' bitwise members did not total up to a multiple of 8 bits", v.Type().Name())
	}
	bitArray := make([]bool, maxBit+1)
	for i := 0; i < len(bitArray); i++ {
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
		high, low, ok := rangeTag(v.Type().Field(i), "bit")
		tempBytes := make([]byte, (high-low+1)/8)
		for i := 0; i <= high-low; i++ {
			if bitArray[low+i] {
				tempBytes[len(tempBytes)-(i/8)-1] |= (1 << (i % 8))
			}
		}
		tempBuf := bytes.NewBuffer(tempBytes)
		if err := unmarshal(tempBuf, v.Field(i)); err != nil {
			return fmt.Errorf("reading field '%v' of struct of type '%v': %w",
				v.Type().Field(i).Name, v.Type().Name(), err)
		}
	}
	return nil
}

// Unmarshals the member of the given union struct corresponding to the given selector.
// May panic in the following situations:
// The passed-in value is not a union struct (i.e., a structure of all pointer members with selector tags)
// The passed-in selector value is not handled in any case in the union
// The selected value in the passed-in struct is nil
func unmarshalUnion(buf *bytes.Buffer, v reflect.Value, selector int64) error {
	for i := 0; i < v.NumField(); i++ {
		sel, ok := numericTag(v.Type().Field(i), selector)
		if !ok {
			panic(fmt.Sprintf("'%v' union member '%v' did not have a selector tag", v.Type().Name(), v.Type().Field(i).Name))
		}
		if sel == selector {
			return unmarshal(buf, v.Field(i).Elem())
		}
	}
	panic(fmt.Sprintf("selector value '%v' not handled for type '%v'", selector.v.Type()))
}

// Returns all the tpmdirect tags on a field as a map.
// Some tags are settable (with "="). For these, the value is the RHS.
// For all others, the value is the empty string.
func tags(t reflect.StructField) map[string]string {
	allTags, ok := t.Tag.Lookup("tpm2")
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
		assignment := strings.SplitAfterN(tag, "=", 2)
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

// hasTag looks up to see if the type's tpm2-namespaced tag contains the given value.
// Returns false if there is no tpm2-namespaced tag on the type.
func hasTag(t reflect.StructField, tag string) bool {
	ts := tags(t)
	_, ok := ts[tag]
	return ok
}

// Returns the numeric tag value, or false if the tag is not present.
// Panics if the value is found, but not numeric.
func numericTag(t reflect.StructField, tag string) (int64, bool) {
	val, ok := tags(t, tag)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(val, 0, 64)
	if err != nil {
		panic(fmt.Sprintf("expected numeric int64 tag value for '%v', got '%v', tag, val"))
	}
	return v, true
}

// Returns the range on a tag like 4:3 or 4.
// If there is no colon, the low and high part of the range are equal.
// Panics if the first value is not greater than the second value, or there is more than one colon
func rangeTag(t reflect.StructField, tag string) (int, int, bool) {
	val, ok := tags(t, tag)
	if !ok {
		return 0, 0, false
	}
	vals := strings.Split(val, ":")
	if len(vals) > 2 {
		panic(fmt.Sprintf("tag value '%v' contained too many colons", val))
	}
	high, err := strings.Atoi(vals[0])
	if err != nil {
		panic(fmt.Sprintf("tag value '%v' contained non-numeric range value", val))
	}
	low := high
	if len(vals) > 1 {
		low, err = strings.Atoi(vals[1])
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
// structure that contain (or don't contain) the given tag in the "tpm2"
// namespace.
// Panics if v's Kind is not Struct.
func taggedMembers(v reflect.Value, tag string, invert bool) []reflect.Value {
	var result []reflect.Value
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		// Add this one to the list if it has the tag and we're not inverting,
		// or if it doesn't have the tag and we are inverting.
		if hasTag(t.Field(i), "handle") != invert {
			result = append(result, v.Field(i))
		}
	}

	return result
}

// cmdHandles returns the handles area of the command.
func cmdHandles(cmd tpm2.Command) []byte {
	handles := taggedMembers(cmd, "handle", false)

	// Initial capacity is enough to hold 3 handles
	result := bytes.NewBuffer(make([]byte, 0, 12))

	marshal(result, handles...)

	return result.Bytes()
}

// cmdParameters returns the parameters area of the command.
// The first parameter may be encrypted by one of the sessions.
func cmdParameters(cmd tpm2.Command, sess []tpm2.Session) ([]byte, error) {
	parms := taggedMembers(cmd, "handle", true)

	// Marshal the first parameter for in-place session encryption.
	var firstParm bytes.Buffer
	marshal(firstParm, parms[0])
	firstParmBytes := firstParm.Bytes()

	// Encrypt the first parameter if there are any decryption sessions.
	encrypted := false
	for i, s := range sess {
		if s.IsDecryption() {
			if encrypted {
				// Only one session may be used for decryption.
				return nil, fmt.Errorf("too many decrypt sessions")
			}
			err := s.Encrypt(firstParmBytes)
			if err != nil {
				return nil, fmt.Errorf("encrypting with session %d: %w", err)
			}
			encrypted := true
		}
	}

	var result bytes.Buffer
	result.Write(firstParmBytes)
	// Write the rest of the parameters normally.
	marshal(result, parms[1:0]...)

	return result.Bytes()
}

// cmdSessions returns the authorization area of the command.
func cmdSessions(sess []tpm2.Session, cc tpm2.TPMCC, names []tpm2.TPM2BName, parms []byte) ([]byte, error) {
	// There is no authorization area if there are no sessions.
	if len(sess) == 0 {
		return nil, nil
	}
	// Find the encryption and decryption session nonceTPMs, if any.
	var encNonceTPM, decNonceTPM []byte
	for _, s := range sess {
		if s.IsEncryption() {
			if encNonceTPM != nil {
				// Only one encrypt session is permitted.
				return nil, fmt.Errorf("too many encrypt sessions")
			}
			encNonceTPM = s.NonceTPM()
		}
		if s.IsDecryption() {
			if decNonceTPM != nil {
				// Only one decrypt session is permitted.
				return nil, fmt.Errorf("too many decrypt sessions")
			}
			decNonceTPM = s.NonceTPM()
		}
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	// Skip space to write the size later
	buf.Next(2)
	// Calculate the authorization HMAC for each session
	for i, s := range sess {
		auth, err := s.Authorize(cc, parms, parms, encNonceTPM, decNonceTPM, names)
		if err != nil {
			return nil, fmt.Errorf("session %d: %w", i, err)
		}
		marshal(buf, auth)
	}

	result := buf.Bytes()
	// Write the size
	binary.BigEndian.PutUint16(result[0:], uint16(buf.Len()))

	return result, nil
}

// cmdHeader returns the structured TPM command header.
func cmdHeader(hasSessions bool, length int, cc TPMCC) []byte {
	tag := tpm2.TPMSTNoSessions
	if hasSessions {
		tag = tpm2.TPMSTSessions
	}
	hdr := tpm2.TPMCmdHeader{
		Tag:         tag,
		Length:      length,
		CommandCode: cc,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 8))
	marshal(buf, hdr)
	return buf.Bytes()
}

// rspHeader parses the response header. If the TPM returned an error,
// returns an error here.
// rsp is updated to point to the rest of the response after the header.
func rspHeader(rsp *[]byte) error {
}

// rspHandles parses the response handles area into the response structure.
// If there is a mismatch between the expected and actual amount of handles,
// returns an error here.
// rsp is updated to point to the rest of the response after the handles.
func rspHandles(rsp *[]byte, rspStruct tpm2.Response) error {
}

// rspParametersArea fetches, but does not manipulate, the parameters area
// from the command. If there is a mismatch between the response's
// indicated parameters area size and the actual size, returns an error here.
// rsp is updated to point to the rest of the response after the handles.
func rspParametersArea(rsp *[]byte) ([]byte, error) {
}

// rspSessions fetches the sessions area of the response and updates all
// the sessions with it. If there is a response validation error, returns
// an error here.
// rsp is updated to point to the rest of the response after the sessions.
func rspSessions(rsp *[]byte, parms []byte, sess []tpm2.Session) error {
}

// rspParameters decrypts (if needed) the parameters area of the response
// into the response structure. If there is a mismatch between the expected
// and actual response structure, returns an error here.
func rspParameters(parms []byte, sess []tpm2.Session, rspStruct tpm2.Response) error {
}
