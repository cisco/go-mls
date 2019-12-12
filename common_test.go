package mls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func assertTrue(t *testing.T, test bool, msg string) {
	t.Helper()
	prefix := string("")
	for i := 1; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		prefix = fmt.Sprintf("%v: %d\n", file, line) + prefix
	}
	if !test {
		t.Fatalf(prefix + msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	assertTrue(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		msg += ": " + err.Error()
	}
	assertTrue(t, err == nil, msg)
}

func assertNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assertTrue(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, bytes.Equal(a, b), fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, !bytes.Equal(a, b), fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertDeepEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assertTrue(t, reflect.DeepEqual(a, b), fmt.Sprintf("%+v != %+v", a, b))
}

func assertSameType(t *testing.T, a, b interface{}) {
	t.Helper()
	A := reflect.TypeOf(a)
	B := reflect.TypeOf(b)
	assertTrue(t, A == B, fmt.Sprintf("%s != %s", A.Name(), B.Name()))
}
