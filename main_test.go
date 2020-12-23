package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
)

var binaryName = "tmpJwt"

func TestMain(m *testing.M) {
	build := exec.Command("go", "build", "-o", binaryName)
	err := build.Run()
	if err != nil {
		fmt.Printf("could not make binary %v", err)
		os.Exit(1)
	}
	exitCode := m.Run()

	cleanUp := exec.Command("rm", "-f", binaryName)
	cleanUperr := cleanUp.Run()
	if cleanUperr != nil {
		fmt.Println("could not clean up", err)
	}

	os.Exit(exitCode)
}

var decodeTestCases = []struct {
	name           string
	jwt            string
	expectedOutput string
}{
	{"hs256", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kXSdJhhUKTJemgs8O0rfIJmUaxoSIDdClL_OPmaC7Eo", "testData/decode/HS256.json"},
	{"hs512", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg", "testData/decode/HS512.json"},
}

func TestDecodeJWT(t *testing.T) {

	for _, tt := range decodeTestCases {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(path.Join(dir, binaryName), []string{"decode", tt.jwt}...)

			out, _ := cmd.Output()

			expected, err := ioutil.ReadFile("./" + tt.expectedOutput)

			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, out) {
				t.Errorf("%v => want %v, but got %v", tt.name, string(expected), string(out))
			}
		})
	}

}

var validateTestCases = []struct {
	name           string
	jwt            string
	expectedOutput string
}{
	{"valid", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kXSdJhhUKTJemgs8O0rfIJmUaxoSIDdClL_OPmaC7Eo", "testData/validate/HS256.json"},
	{"incorrect signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kiLK7xLmGyLdcwYDzwJfHE8Wa42STGYLgtpzEiYqKhQ", "testData/validate/invalid-signature.out"},
	{"not a jwt", "notajwt", "testData/validate/not-a-jwt.out"},
}

func TestValidateJWT(t *testing.T) {

	for _, tt := range validateTestCases {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(path.Join(dir, binaryName), []string{"validate", "--secret", "password", tt.jwt}...)

			out, _ := cmd.Output()

			expected, err := ioutil.ReadFile("./" + tt.expectedOutput)

			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, out) {
				t.Errorf("%v => want %v, but got %v", tt.name, string(expected), string(out))
			}
		})
	}

}

var encodeTestCases = []struct {
	name        string
	alg         string
	secret      string
	expectedJWT string
}{
	{"HS256", "HS256", "password", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.mjqxkG2vFF0jUjF7V4DTqQ8-YMmEXPEbi8U1mCuSNh0"},
	{"HS512", "HS512", "password", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.FKMAbYE3lNdalkkgs6GKb14hC9z2lkIxyTLP0ZLR6GB3WqS9AfSJik7Fsw1vEs0SuBmZRJtvQibukS0kM24sHA"},
}

func TestEncodeJWT(t *testing.T) {

	for _, tt := range encodeTestCases {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			payloadBytes, err := ioutil.ReadFile("./testData/encode/payload.json")
			if err != nil {
				t.Fatal(err)
			}
			payload := string(payloadBytes)
			cmd := exec.Command(path.Join(dir, binaryName), []string{"encode", "--alg", tt.alg, "--secret", tt.secret, payload}...)

			out, _ := cmd.Output()

			if tt.expectedJWT != strings.TrimSpace(string(out)) {
				t.Errorf("%v => want %v, but got %v", tt.name, tt.expectedJWT, string(out))
			}
		})
	}

}
