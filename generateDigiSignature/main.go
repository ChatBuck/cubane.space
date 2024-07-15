package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
)

type Transaction struct {
	SenderPublicKey string `json:"sender_public_key"`
	Recipient       string `json:"recipient"`
	Amount          int    `json:"amount"`
	Fee             int    `json:"fee"`
	Nonce           int    `json:"nonce"`
	Signature       string `json:"signature"`
}

func generateWallet() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

func signTransaction(transaction *Transaction, privateKeyPEM string) error {
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return err
	}

	txData, err := json.Marshal(transaction)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(txData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return err
	}

	transaction.Signature = hex.EncodeToString(signature)
	return nil
}

func main() {
	// Generate three wallets
	wallet1Private, wallet1Public, err := generateWallet()
	if err != nil {
		log.Fatalf("Failed to generate wallet 1: %v", err)
	}
	wallet2Private, wallet2Public, err := generateWallet()
	if err != nil {
		log.Fatalf("Failed to generate wallet 2: %v", err)
	}

	fmt.Println("Wallet 1 Private Key:\n", wallet1Private)
	fmt.Println("Wallet 1 Public Key:\n", wallet1Public)
	fmt.Println("\nWallet 2 Private Key:\n", wallet2Private)
	fmt.Println("Wallet 2 Public Key:\n", wallet2Public)

	// Create a transaction from wallet 1 to wallet 2
	transaction := &Transaction{
		SenderPublicKey: wallet1Public,
		Recipient:       wallet2Public,
		Amount:          100,
		Fee:             1,
		Nonce:           0,
	}

	// Sign the transaction using wallet 1's private key
	err = signTransaction(transaction, wallet1Private)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Print the signed transaction
	signedTxData, err := json.MarshalIndent(transaction, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal signed transaction: %v", err)
	}
	fmt.Println("\nSigned Transaction:\n", string(signedTxData))

	// Send the transaction to the blockchain node
	url := "http://localhost:9080/transaction"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(signedTxData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)
}
