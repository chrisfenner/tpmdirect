// package tpmdirect is the reflection-based implementation of TPMDirect
package tpmdirect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"

	"github.com/chrisfenner/tpmdirect/tpm2"
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
			marshalSlice(buf, v)
		case reflect.Struct:
			marshalStruct(buf, v)
		case reflect.Ptr:
			// Pointers are used for union members. Only non-nil members
			// are marshalled.
			if !v.IsNil() {
				marshal(buf, v.Elem())
			}
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

func marshalSlice(buf *bytes.Buffer, v reflect.Value) {
	if err := binary.Write(buf, binary.BigEndian, v.Interface()); err != nil {
		panic(err)
	}
}

func marshalStruct(buf *bytes.Buffer, v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {

	}
}

// hasTag looks up to see if the type's tpm2-namespaced tag contains the given value.
// Returns false if there is no tpm2-namespaced tag on the type.
func hasTag(t reflect.StructField, tag string) bool {
	thisTag, ok := t.Tag.Lookup("tpm2")
	return ok && strings.Contains(thisTag, tag)
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

	var buf bytes.Buffer
	// Calculate the authorization HMAC for each session
	for i, s := range sess {
		auth, err := s.Authorize(cc, parms, parms, encNonceTPM, decNonceTPM, names)
		if err != nil {
			return nil, fmt.Errorf("session %d: %w", i, err)
		}
		marshal(&buf, auth)
	}

	return buf.Bytes(), nil
}

// cmdHeader returns the structured TPM command header.
func cmdHeader(hasSessions bool, restOfCommandLen int, cc TPMCC) []byte {
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
