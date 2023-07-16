package main

import (
	"bufio"
	"fmt"
	"os"
)

// Codebook for CFB
var codebookCFB = [4][2]int{{0b00, 0b01}, {0b01, 0b10}, {0b10, 0b11}, {0b11, 0b00}}
var message = [4]int{0b00, 0b01, 0b10, 0b11}
var cipher = [4]int{}
var iv = 0b10

// Codebook for ECB/OFB
var codebookMap = map[string]string{
	"a": "01100001",
	"b": "01100010",
	"c": "01100011",
	"d": "01100100",
	"e": "01100101",
	"f": "01100110",
	"g": "01100111",
	"h": "01101000",
	"i": "01101001",
	"j": "01101010",
	"k": "01101011",
	"l": "01101100",
	"m": "01101101",
	"n": "01101110",
	"o": "01101111",
	"p": "01110000",
	"q": "01110001",
	"r": "01110010",
	"s": "01110011",
	"t": "01110100",
	"u": "01110101",
	"v": "01110110",
	"w": "01110111",
	"x": "01111000",
	"y": "01111001",
	"z": "01111010",
	"A": "01000001",
	"B": "01000010",
	"C": "01000011",
	"D": "01000100",
	"E": "01000101",
	"F": "01000110",
	"G": "01000111",
	"H": "01001000",
	"I": "01001001",
	"J": "01001010",
	"K": "01001011",
	"L": "01001100",
	"M": "01001101",
	"N": "01001110",
	"O": "01001111",
	"P": "01010000",
	"Q": "01010001",
	"R": "01010010",
	"S": "01010011",
	"T": "01010100",
	"U": "01010101",
	"V": "01010110",
	"W": "01010111",
	"X": "01011000",
	"Y": "01011001",
	"Z": "01011010",
}

// Function for CFB
func codebookLookup(xor int) int {
	var lookupValue int
	for i := 0; i < 4; i++ {
		if codebookCFB[i][0] == xor {
			lookupValue = codebookCFB[i][1]
			break
		}
	}
	return lookupValue
}

// Function for ECB
func ecbEncrypt(plaintext string) string {
	ciphertext := ""
	for _, char := range plaintext {
		code, ok := codebookMap[string(char)]
		if ok {
			ciphertext += code
		} else {
			// Handle characters not found in the codebook
			ciphertext += string(char)
		}
	}
	return ciphertext
}

// Perform OFB encryption
func ofbEncrypt(plaintext string) string {
	ciphertext := ""
	previousBlock := fmt.Sprintf("%08b", iv)
	for _, char := range plaintext {
		code, ok := codebookMap[string(char)]
		if ok {
			block := xorStrings(code, previousBlock)
			ciphertext += block
			previousBlock = block
		} else {
			// Handle characters not found in the codebook
			ciphertext += string(char)
		}
	}
	return ciphertext
}

// Perform CBC encryption
func cbcEncrypt(plaintext, iv string) string {
	ciphertext := ""
	previousBlock := iv
	for _, char := range plaintext {
		code, ok := codebookMap[string(char)]
		if ok {
			block := xorStrings(code, previousBlock)
			ciphertext += block
			previousBlock = block
		} else {
			// Handle characters not found in the codebook
			ciphertext += string(char)
		}
	}
	return ciphertext
}

// XOR two binary strings for OFB and CBC
func xorStrings(a, b string) string {
	result := ""
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			result += "0"
		} else {
			result += "1"
		}
	}
	return result
}

func main() {
	var xor int
	var lookupValue int
	lookupValue = codebookLookup(iv)

	fmt.Println("CFB")

	// CFB Plaintext
	for i := 0; i < 4; i++ {
		fmt.Printf("The plaintext value of a is %02b\n", message[i])
	}

	// Perform CFB Ciphertext
	for i := 0; i < 4; i++ {
		xor = message[i] ^ lookupValue
		lookupValue = codebookLookup(xor)
		fmt.Printf("The ciphertext value of a is %02b\n", xor)
		cipher[i] = xor
	}

	// Perform CFB Plaintext
	lookupValue = codebookLookup(iv)
	for i := 0; i < 4; i++ {
		xor = cipher[i] ^ lookupValue
		lookupValue = codebookLookup(cipher[i])
		fmt.Printf("The plaintext value of a is %02b\n", xor)
	}

	fmt.Println("ECB")

	// Read plaintext from user (ECB)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the plaintext: ")
	plaintext, _ := reader.ReadString('\n')

	// Perform ECB encryption
	ciphertext := ecbEncrypt(plaintext)

	// Display ECB details
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Ciphertext:", ciphertext)

	fmt.Println("OFB")

	// Read plaintext from user (OFB)
	fmt.Print("Enter a line of text: ")
	plaintext, _ = reader.ReadString('\n')

	// Perform OFB encryption
	ciphertext = ofbEncrypt(plaintext)

	// Display OFB details
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Ciphertext:", ciphertext)

	fmt.Println("CBC")

	// Read plaintext from user (CBC)
	fmt.Print("Enter a line of text: ")
	plaintext, _ = reader.ReadString('\n')

	fmt.Print("Enter the Initialization Vector (IV) for CBC: ")
	cbcIVInput, _ := reader.ReadString('\n')
	cbcIV := cbcIVInput[:len(cbcIVInput)-1]

	// Perform CBC encryption
	ciphertext = cbcEncrypt(plaintext, cbcIV)

	// Display CBC details
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("IV (CBC):", cbcIV)
	fmt.Println("Ciphertext:", ciphertext)
}
