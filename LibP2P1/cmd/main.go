package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	golog "github.com/ipfs/go-log"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/core/crypto"
	host "github.com/libp2p/go-libp2p/core/host"
	net "github.com/libp2p/go-libp2p/core/network"
	peer2 "github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	gologging "github.com/whyrusleeping/go-logging"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Transaction struct {
	SenderPublicKey string `json:"sender_public_key"`
	Recipient       string `json:"recipient"`
	Amount          int    `json:"amount"`
	Fee             int    `json:"fee"`
	Nonce           int    `json:"nonce"`
	Signature       string `json:"signature"`
}

type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Hash         string        `json:"hash"`
	PrevHash     string        `json:"prev_hash"`
}

var Blockchain []Block
var mutex = &sync.Mutex{}

func makeBasicHost(listenPort int, secio bool, randseed int64) (host.Host, error) {
	var r io.Reader
	if randseed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(randseed))
	}

	rsaKeyPair, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	priv := rsaKeyPair

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", listenPort)),
		libp2p.Identity(priv),
	}

	basicHost, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().String()))
	addrs := basicHost.Addrs()
	var addr ma.Multiaddr
	for _, i := range addrs {
		if strings.HasPrefix(i.String(), "/ip4") {
			addr = i
			break
		}
	}
	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)
	if secio {
		log.Printf("Now run \"go run main.go -l %d -d %s -secio\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}

	return basicHost, nil
}

func handleStream(s net.Stream) {
	log.Println("Got a new stream!")
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	go readData(rw)
	go writeData(rw)
}

func readData(rw *bufio.ReadWriter) {
	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		if str == "" {
			return
		}
		if str != "\n" {
			chain := make([]Block, 0)
			if err := json.Unmarshal([]byte(str), &chain); err != nil {
				log.Fatal(err)
			}
			mutex.Lock()
			if len(chain) > len(Blockchain) {
				Blockchain = chain
				bytes, err := json.MarshalIndent(Blockchain, "", "  ")
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			}
			mutex.Unlock()
		}
	}
}

func writeData(rw *bufio.ReadWriter) {
	go func() {
		for {
			time.Sleep(5 * time.Second)
			mutex.Lock()
			bytes, err := json.Marshal(Blockchain)
			if err != nil {
				log.Println(err)
			}
			mutex.Unlock()

			mutex.Lock()
			rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
			rw.Flush()
			mutex.Unlock()
		}
	}()
}

type TransactionInput struct {
	SenderPublicKey string `json:"sender_public_key"`
	Recipient       string `json:"recipient"`
	Amount          int    `json:"amount"`
	Fee             int    `json:"fee"`
	Nonce           int    `json:"nonce"`
	Signature       string `json:"signature"`
}

//func verifySignature(pubKeyPEM, signatureHex string, tx Transaction) bool {
//	block, _ := pem.Decode([]byte(pubKeyPEM))
//	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
//	if err != nil {
//		log.Println("Failed to parse public key:", err)
//		return false
//	}
//
//	pubKey := pubKeyInterface.(*rsa.PublicKey)
//
//	signatureBytes, err := hex.DecodeString(signatureHex)
//	if err != nil {
//		log.Println("Failed to decode signature:", err)
//		return false
//	}
//
//	txData, err := json.Marshal(tx)
//	if err != nil {
//		log.Println("Failed to marshal transaction:", err)
//		return false
//	}
//
//	hash := sha256.Sum256(txData)
//	err = rsa.VerifyPKCS1v15(pubKey, stdCrypto.SHA256, hash[:], signatureBytes)
//	if err != nil {
//		log.Println("Failed to verify signature:", err)
//		return false
//	}
//
//	return true
//}

func handleTransaction(w http.ResponseWriter, r *http.Request) {
	var txInput TransactionInput
	if err := json.NewDecoder(r.Body).Decode(&txInput); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	newTransaction := Transaction{
		SenderPublicKey: txInput.SenderPublicKey,
		Recipient:       txInput.Recipient,
		Amount:          txInput.Amount,
		Fee:             txInput.Fee,
		Nonce:           txInput.Nonce,
		Signature:       txInput.Signature,
	}

	//if !verifySignature(newTransaction.SenderPublicKey, newTransaction.Signature, newTransaction) {
	//	http.Error(w, "Invalid transaction signature", http.StatusUnauthorized)
	//	return
	//}

	newBlock := generateBlock(Blockchain[len(Blockchain)-1], []Transaction{newTransaction})

	if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
		mutex.Lock()
		Blockchain = append(Blockchain, newBlock)
		mutex.Unlock()
	}

	bytes, err := json.Marshal(Blockchain)
	if err != nil {
		http.Error(w, "Failed to marshal blockchain", http.StatusInternalServerError)
		return
	}

	spew.Dump(Blockchain)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + transactionsToString(block.Transactions) + block.PrevHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func generateBlock(oldBlock Block, transactions []Transaction) Block {
	var newBlock Block
	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Transactions = transactions
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	return newBlock
}

func transactionsToString(transactions []Transaction) string {
	var transactionStrings []string
	for _, txn := range transactions {
		txBytes, _ := json.Marshal(txn)
		transactionStrings = append(transactionStrings, string(txBytes))
	}
	return strings.Join(transactionStrings, ",")
}

func main() {
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, t.String(), []Transaction{}, calculateHash(genesisBlock), ""}

	Blockchain = append(Blockchain, genesisBlock)

	golog.SetAllLoggers(golog.LogLevel(gologging.INFO))

	listenF := flag.Int("l", 0, "wait for incoming connections")
	target := flag.String("d", "", "target peer to dial")
	secio := flag.Bool("secio", false, "enable secio")
	seed := flag.Int64("seed", 0, "set random seed for id generation")
	flag.Parse()

	if *listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	ha, err := makeBasicHost(*listenF, *secio, *seed)
	if err != nil {
		log.Fatal(err)
	}

	httpPort := *listenF + 1000
	http.HandleFunc("/transaction", handleTransaction)
	go func() {
		log.Printf("Starting HTTP server on port %d\n", httpPort)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil))
	}()

	if *target == "" {
		log.Println("Listening for connections")
		ha.SetStreamHandler("/p2p/1.0.0", handleStream)
		select {}
	} else {
		ha.SetStreamHandler("/p2p/1.0.0", handleStream)

		ipfsaddr, err := ma.NewMultiaddr(*target)
		if err != nil {
			log.Fatalln(err)
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Fatalln(err)
		}

		peerid, err := peer.IDB58Decode(pid)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Target Peer ID:", peer.IDB58Encode(peerid))

		targetPeerAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)
		log.Println("targetAddr : ", targetAddr)
		log.Println("Adding peer to peerstore")
		ttl := time.Hour
		ha.Peerstore().AddAddr(peer2.ID(peerid), targetAddr, ttl)

		log.Println("opening stream")
		s, err := ha.NewStream(context.Background(), peer2.ID(peerid), "/p2p/1.0.0")
		if err != nil {
			log.Fatalln(err)
		}

		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
		go writeData(rw)
		go readData(rw)

		select {}
	}
}
