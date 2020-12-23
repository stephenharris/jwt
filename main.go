package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gookit/color"
)

const (
	DECODE   = "decode"
	ENCODE   = "encode"
	VALIDATE = "validate"
	HELP     = "help"
)

var (
	// Options
	validateCommand  = flag.NewFlagSet("validate", flag.ExitOnError)
	validateSecret   = validateCommand.String("secret", "", "The signing secret")
	validateHelpFlag = validateCommand.Bool("help", false, "Help")

	decodeCommand  = flag.NewFlagSet("decode", flag.ExitOnError)
	decodeHelpFlag = decodeCommand.Bool("help", false, "Help")

	encodeCommand  = flag.NewFlagSet("encode", flag.ExitOnError)
	encodeSecret   = encodeCommand.String("secret", "", "The signing secret")
	encodeAlg      = encodeCommand.String("alg", "", "The algorithm")
	encodeHelpFlag = encodeCommand.Bool("help", false, "Help")
)

func main() {

	cmd := "help"

	if len(os.Args) > 1 {
		cmd = strings.ToLower(os.Args[1])
	}

	switch cmd {
	case DECODE:
		decodeCommand.Parse(os.Args[2:])

		if *decodeHelpFlag {
			decodeUsage()
			os.Exit(0)
		}

		decodeJWT(decodeCommand.Arg(0))

	case VALIDATE:
		validateCommand.Parse(os.Args[2:])

		if *validateHelpFlag {
			validateUsage()
			os.Exit(0)
		}

		validateJWT(validateCommand.Arg(0), *validateSecret)

	case ENCODE:
		encodeCommand.Parse(os.Args[2:])

		if *encodeHelpFlag {
			encodeUsage()
			os.Exit(0)
		}

		encodeJWT(encodeCommand.Arg(0))

	default:
		fmt.Println("Encodes, decode and validate JWTs.\n ")
		fmt.Printf("%s encode [OPTIONS] <json-encoded-payload>\t Encodes a JWT\n", os.Args[0])
		fmt.Printf("%s decode [OPTIONS] <jwt>\t\t\t Decodes a JWT, without validating it\n", os.Args[0])
		fmt.Printf("%s validate [OPTIONS] <jwt>\t\t\t Decodes & verfies a JWT's claims and signature\n\n", os.Args[0])
		fmt.Printf("Use the %s <cmd> --help for more information\n", os.Args[0])
	}
}

func decodeJWT(jwtStr string) {
	// Parse the token.  Load the key from command line option
	token, err := jwt.Parse(jwtStr, nil)

	if token == nil {
		if err != nil {
			printError(err)
		} else {
			printError(errors.New("Invalid token"))
		}
	}

	tokenContents := struct {
		Header  interface{} `json:"header"`
		Payload interface{} `json:"payload"`
	}{
		token.Header,
		token.Claims,
	}

	printJson(tokenContents)

}

func validateJWT(jwtStr string, secret string) {

	token, err := jwt.Parse(string(jwtStr), func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		printError(err)
	} else if token == nil {
		printError(errors.New("Invalid token"))
	}

	tokenContents := struct {
		Header  interface{} `json:"header"`
		Payload interface{} `json:"payload"`
	}{
		token.Header,
		token.Claims,
	}

	printJson(tokenContents)

}

func encodeJWT(data string) {

	// parse the JSON of the claims
	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(data), &claims); err != nil {
		printError(fmt.Errorf("Couldn't parse claims JSON: %v", err))
	}

	// get the key
	secret := *encodeSecret

	// get the signing alg
	alg := jwt.GetSigningMethod(*encodeAlg)

	if alg == nil {
		printError(fmt.Errorf("Couldn't find signing method: %v", *encodeAlg))
	}

	// create a new token
	token := jwt.NewWithClaims(alg, claims)

	if out, err := token.SignedString([]byte(secret)); err == nil {
		fmt.Println(out)
	} else {
		printError(err)
	}
}

func printJson(data interface{}) {
	var out []byte
	var err error
	out, err = json.MarshalIndent(data, "", "    ")

	if err == nil {
		fmt.Println(string(out))
	}
}

func validateUsage() {
	fmt.Println("Verifies a JWT's claims and signature.\n ")
	fmt.Printf("Usage: \n  %s validate [OPTIONS] <jwt>\n\n", os.Args[0])
	fmt.Printf("Example: \n  %s validate --secret password eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.-fKGu6c4VNyGzGuzG1M0Cx87gyYFxM3-o2H_vRAnfVY\n\n", os.Args[0])
	fmt.Println("Options:")
	validateCommand.PrintDefaults()
}

func decodeUsage() {
	fmt.Println("Displays a JWT's claims without performing any verification of them or the signature.\n ")
	fmt.Printf("Usage: \n  %s decode [OPTIONS] <jwt>\n\n", os.Args[0])
	fmt.Printf("Example: \n  %s decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.-fKGu6c4VNyGzGuzG1M0Cx87gyYFxM3-o2H_vRAnfVY\n\n", os.Args[0])
	fmt.Println("Options:")
	decodeCommand.PrintDefaults()
}

func encodeUsage() {
	fmt.Println("Encodes a JWT.\n ")
	fmt.Printf("Usage: \n  %s encode [OPTIONS] <json-encoded-payload>\n\n", os.Args[0])
	fmt.Printf("Example: \n  %s encode --alg HS256 --secret password '{\"foo\":\"bar\"}'\n\n", os.Args[0])
	fmt.Println("Options:")
	encodeCommand.PrintDefaults()
}

func printError(err error) {
	color.Error.Printf("error: %v", err)
	fmt.Println("")
	os.Exit(1)
}
