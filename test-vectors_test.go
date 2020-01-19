package mls

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// To generate or verify test vectors, run `go test` with these environment
// variables set to point to the directory where the test files reside.  The
// names of the individual files of test vectors are specified in the test
// vector cases below.
//
// > MLS_TEST_VECTORS_OUT=... go test -run VectorGen
// > MLS_TEST_VECTORS_IN=...  go test -run VectorVer
const (
	testDirWriteEnv = "MLS_TEST_VECTORS_OUT"
	testDirReadEnv  = "MLS_TEST_VECTORS_IN"
)

// For each set of test vectors, this struct defines:
//
// * The file name with which the vectors should be saved / loaded
// * A function to generate test vectors
// * A function to verify test vectors
//
// The generate and verify functions are responsible for reporting their own
// errors through the testing.T object passed to them.  The functions themselves
// should be defined in the test files for the relevant modules.
type TestVectorCase struct {
	Filename string
	Generate func(t *testing.T) []byte
	Verify   func(t *testing.T, data []byte)
}

var testVectorCases = map[string]TestVectorCase{
	"tree_math": {
		Filename: "tree_math.bin",
		Generate: generateTreeMathVectors,
		Verify:   verifyTreeMathVectors,
	},

	"crypto": {
		Filename: "crypto.bin",
		Generate: generateCryptoVectors,
		Verify:   verifyCryptoVectors,
	},

	"messages": {
		Filename: "messages.bin",
		Generate: generateMessageVectors,
		Verify:   verifyMessageVectors,
	},

	"key_schedule": {
		Filename: "key_schedule.bin",
		Generate: generateKeyScheduleVectors,
		Verify:   verifyKeyScheduleVectors,
	},

	"ratchet_tree": {
		Filename: "tree.bin",
		Generate: generateRatchetTreeVectors,
		Verify:   verifyRatchetTreeVectors,
	},
	// TODO continue
}

func vectorGenerate(c TestVectorCase, testDir string) func(t *testing.T) {
	return func(t *testing.T) {
		// Generate test vectors
		vec := c.Generate(t)

		// Verify that vectors pass
		c.Verify(t, vec)

		// Write the vectors to file if required
		if len(testDir) != 0 {
			file := filepath.Join(testDir, c.Filename)
			err := ioutil.WriteFile(file, vec, 0644)
			assertNotError(t, err, "Error writing test vectors")
		}
	}
}

func TestVectorGenerate(t *testing.T) {
	testDir := os.Getenv(testDirWriteEnv)

	for label, tvCase := range testVectorCases {
		t.Run(label, vectorGenerate(tvCase, testDir))
	}
}

func vectorVerify(c TestVectorCase, testDir string) func(t *testing.T) {
	return func(t *testing.T) {
		// Read test vectors
		file := filepath.Join(testDir, c.Filename)
		fmt.Printf("Test File %v\n", file)
		vec, err := ioutil.ReadFile(file)
		assertNotError(t, err, "Error reading test vectors")

		// Verify test vectors
		c.Verify(t, vec)
	}
}

func TestVectorVerify(t *testing.T) {
	testDir := ""
	if testDir = os.Getenv(testDirReadEnv); len(testDir) == 0 {
		t.Skip("Test vectors were not provided")
	}

	for label, tvCase := range testVectorCases {
		t.Run(label, vectorVerify(tvCase, testDir))
	}
}
