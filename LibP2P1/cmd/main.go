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
	"github.com/libp2p/go-libp2p-kad-dht"
)

var (
    bootstrapAddr = flag.String("bootstrap", "", "Bootstrap node multiaddr")
    port          = flag.String("port", "8080", "Port for the REST API")
    node          host.Host
)

type Transaction struct {
	SenderPublicKey string `json:"sender_public_key"`
	Recipient       string `json:"recipient"`
	Amount          int    `json:"amount"`
	Fee             int    `json:"fee"`
	Nonce           int    `json:"nonce"`
	Signature       string `json:"signature"`
	TokenType 		string `json:"token_type"`
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

type CubsToken struct {
    Balance map[string]int
}

func NewCubsToken() *CubsToken {
    return &CubsToken{Balance: make(map[string]int)}
}

func (token *CubsToken) Mint(address string, amount int) {
    token.Balance[address] += amount
}

func (token *CubsToken) Transfer(from, to string, amount int) bool {
    if token.Balance[from] >= amount {
        token.Balance[from] -= amount
        token.Balance[to] += amount
        return true
    }
    return false
}

var cubsToken = NewCubsToken()

func createHost(ctx context.Context) (host.Host, error) {
    h, err := libp2p.New(libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", *port)))
    if err != nil {
        return nil, err
    }

    dht, err := dht.New(ctx, h)
    if err != nil {
        return nil, err
    }

    if *bootstrapAddr != "" {
        log.Printf("Connecting to bootstrap node: %s", *bootstrapAddr)
        maddr, err := ma.NewMultiaddr(*bootstrapAddr)
        if err != nil {
            return nil, fmt.Errorf("invalid bootstrap multiaddr: %v", err)
        }
        peerinfo, err := peer.AddrInfoFromP2pAddr(maddr)
        if err != nil {
            return nil, fmt.Errorf("error parsing bootstrap peer info: %v", err)
        }
        if err := h.Connect(ctx, *peerinfo); err != nil {
            log.Printf("Error connecting to bootstrap node: %v", err)
        } else {
            log.Printf("Successfully connected to bootstrap node: %s", *bootstrapAddr)
        }
    }

    return h, nil
}

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
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)),
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
	TokenType 		string `json:"token_type"`
}


func handleTransaction(w http.ResponseWriter, r *http.Request) {
    log.Println("Received a transaction request")
    var txInput TransactionInput
    if err := json.NewDecoder(r.Body).Decode(&txInput); err != nil {
        log.Println("Invalid transaction input:", err)
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }
    log.Printf("Processing transaction: %+v", txInput)

    if txInput.TokenType != "CubsToken" {
        log.Println("Transaction rejected: Unsupported token type")
        http.Error(w, "Only CubsToken transactions are allowed", http.StatusBadRequest)
        return
    }

    if cubsToken.Balance[txInput.SenderPublicKey] < txInput.Amount+txInput.Fee {
        log.Println("Transaction rejected: Insufficient CubsToken balance")
        http.Error(w, "Insufficient CubsToken balance", http.StatusBadRequest)
        return
    }

    cubsToken.Transfer(txInput.SenderPublicKey, txInput.Recipient, txInput.Amount)
    cubsToken.Balance[txInput.SenderPublicKey] -= txInput.Fee
    log.Println("Transaction completed successfully, creating new block")

    newTransaction := Transaction{
        SenderPublicKey: txInput.SenderPublicKey,
        Recipient:       txInput.Recipient,
        Amount:          txInput.Amount,
        Fee:             txInput.Fee,
        Nonce:           txInput.Nonce,
        Signature:       txInput.Signature,
        TokenType:       txInput.TokenType,
    }

    newBlock := generateBlock(Blockchain[len(Blockchain)-1], []Transaction{newTransaction})

    if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
        mutex.Lock()
        Blockchain = append(Blockchain, newBlock)
        mutex.Unlock()
        log.Println("New block added to the blockchain:", newBlock.Index)
    } else {
        log.Println("New block validation failed")
    }

    bytes, err := json.Marshal(Blockchain)
    if err != nil {
        log.Println("Error marshaling blockchain:", err)
        http.Error(w, "Failed to marshal blockchain", http.StatusInternalServerError)
        return
    }

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

func handleFaucet(w http.ResponseWriter, r *http.Request) {
    address := r.URL.Query().Get("address")
    if address == "" {
        log.Println("Faucet request failed: Address required")
        http.Error(w, "Address required", http.StatusBadRequest)
        return
    }

    amount := 10
    cubsToken.Mint(address, amount)
    log.Printf("Minted %d CubsToken to address %s", amount, address)
    fmt.Fprintf(w, "Minted %d CubsToken to address %s", amount, address)
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
    // Dummy implementation; replace with real blockchain data retrieval
    blockchain := []Block{{Index: 0, Timestamp: time.Now().String()}}
    json.NewEncoder(w).Encode(blockchain)
}

func getBlockByHeight(w http.ResponseWriter, r *http.Request) {
    // Dummy block retrieval by height; replace with real data
    height := r.URL.Query().Get("height")
    if height == "" {
        http.Error(w, "Height not specified", http.StatusBadRequest)
        return
    }
    block := Block{Index: 0, Timestamp: time.Now().String()}
    json.NewEncoder(w).Encode(block)
}
func main() {
	flag.Parse()
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, t.String(), []Transaction{}, calculateHash(genesisBlock), ""}

	Blockchain = append(Blockchain, genesisBlock)
	cubsToken.Mint("genesisAddress", 1000000)
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
	dht, err := dht.New(context.Background(), ha)
	if err != nil {
		log.Fatal("Error initializing DHT:", err)
	}

	err = dht.Bootstrap(context.Background())
	if err != nil {
		log.Fatal("Error bootstrapping DHT:", err)
	}

	httpPort := *listenF + 1000
	http.HandleFunc("/transaction", handleTransaction)
	http.HandleFunc("/faucet", handleFaucet)
	http.HandleFunc("/blockchain", getBlockchain)
    http.HandleFunc("/block", getBlockByHeight)
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
