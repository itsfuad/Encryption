package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// Generate RSA Key Pair
func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// Save Private Key
func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	if err := pem.Encode(outFile, privateKeyBlock); err != nil {
		return err
	}

	return nil
}

// Save Public Key
func savePublicPEMKey(fileName string, pubkey *rsa.PublicKey) error {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}
	pubkeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	}

	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if err := pem.Encode(outFile, pubkeyBlock); err != nil {
		return err
	}

	return nil
}

// Encrypt File
func encryptFile(filename string, pubkey *rsa.PublicKey) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, data, nil)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename+".enc", encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Load Public Key
func loadPublicKey(fileName string) (*rsa.PublicKey, error) {
	pubKeyFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer pubKeyFile.Close()

	pemFileInfo, _ := pubKeyFile.Stat()
	var size int64 = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(pubKeyFile)
	_, err = buffer.Read(pemBytes)

	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

// Decrypt File
func decryptFile(filename string, privkey *rsa.PrivateKey) error {
	encryptedData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, encryptedData, nil)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename+".dec", decryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Load Private Key
func loadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	privKeyFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer privKeyFile.Close()

	pemFileInfo, _ := privKeyFile.Stat()
	var size int64 = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(privKeyFile)
	_, err = buffer.Read(pemBytes)

	block, _ := pem.Decode(pemBytes)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func main() {
	// Generate RSA key pair
	privateKey, publicKey, err := generateKeyPair(2048)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	// Save keys to files
	err = savePEMKey("private.pem", privateKey)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	err = savePublicPEMKey("public.pem", publicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	fmt.Println("Keys generated and saved.")

	// Load public key
	pubKey, err := loadPublicKey("public.pem")
	if err != nil {
		fmt.Println("Error loading public key:", err)
		return
	}

	// Encrypt file
	err = encryptFile("myfile.txt", pubKey)
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	fmt.Println("File encrypted.")

	// Load private key
	privKey, err := loadPrivateKey("private.pem")
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	// Decrypt file
	err = decryptFile("myfile.txt.enc", privKey)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}

	fmt.Println("File decrypted.")
}
