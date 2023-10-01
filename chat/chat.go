package chat

import (
	"crypto/ecdsa"
	"crypto/rand"

	// "crypto/rsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/triyam/golang-blockchain/utils"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

//chat variable for one to one chatting
type ChatOne2One struct {
	senderPrivateKey           string
	senderPublicKey            string
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	Chat                       string
}

//chat variable for group chats
type ChatGroup2One struct {
	senderPrivateKey           string
	senderPublicKey            string
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	Chat                       string
}

//conversation id entails senderBlockchainAdress and recipientBlockchainAddress
type ConversationId struct {
	senderBlockchainAddress    string
	recipientBlockchainAddress string
}

//defines a grp,it's private and public address and blockchainAddress
type Group struct {
	privateKey        *ecdsa.PrivateKey
	publicKey         *ecdsa.PublicKey
	blockchainAddress string
}

//creates and returns new group
func NewGroup() *Group {
	// 1. Creating ECDSA private key (32 bytes) public key (64 bytes)
	w := new(Group)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w.privateKey = privateKey
	w.publicKey = &w.privateKey.PublicKey
	// 2. Perform SHA-256 hashing on the public key (32 bytes).
	h2 := sha256.New()
	h2.Write(w.publicKey.X.Bytes())
	h2.Write(w.publicKey.Y.Bytes())
	digest2 := h2.Sum(nil)
	// 3. Perform RIPEMD-160 hashing on the result of SHA-256 (20 bytes).
	h3 := ripemd160.New()
	h3.Write(digest2)
	digest3 := h3.Sum(nil)
	// 4. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network).
	vd4 := make([]byte, 21)
	vd4[0] = 0x00
	copy(vd4[1:], digest3[:])
	// 5. Perform SHA-256 hash on the extended RIPEMD-160 result.
	h5 := sha256.New()
	h5.Write(vd4)
	digest5 := h5.Sum(nil)
	// 6. Perform SHA-256 hash on the result of the previous SHA-256 hash.
	h6 := sha256.New()
	h6.Write(digest5)
	digest6 := h6.Sum(nil)
	// 7. Take the first 4 bytes of the second SHA-256 hash for checksum.
	chsum := digest6[:4]
	// 8. Add the 4 checksum bytes from 7 at the end of extended RIPEMD-160 hash from 4 (25 bytes).
	dc8 := make([]byte, 25)
	copy(dc8[:21], vd4[:])
	copy(dc8[21:], chsum[:])
	// 9. Convert the result from a byte string into base58.
	address := base58.Encode(dc8)
	w.blockchainAddress = address
	return w
}

//returns private key for a group
func (w *Group) PrivateKey() *ecdsa.PrivateKey {
	return w.privateKey
}

//returns private key for a group in string format
func (w *Group) PrivateKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

//returns public Key for a group
func (w *Group) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}

//returns public Key string for a group
func (w *Group) PublicKeyStr() string {
	return fmt.Sprintf("%064x%064x", w.publicKey.X.Bytes(), w.publicKey.Y.Bytes())
}

//returns blockchain address for a group
func (w *Group) BlockchainAddress() string {
	return w.blockchainAddress
}


func (w *Group) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PrivateKey        string `json:"private_key"`
		PublicKey         string `json:"public_key"`
		BlockchainAddress string `json:"blockchain_address"`
	}{
		PrivateKey:        w.PrivateKeyStr(),
		PublicKey:         w.PublicKeyStr(),
		BlockchainAddress: w.BlockchainAddress(),
	})
}


type ChatMessage struct {
	senderPrivateKey           *ecdsa.PrivateKey
	senderPublicKey            *ecdsa.PublicKey
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	chat                       string
}

//returns chat in format of ChatMessage
func NewChat(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey,
	sender string, recipient string, chat string) *ChatMessage {
	return &ChatMessage{privateKey, publicKey, sender, recipient, chat}
}

//returns signed chat signature
func (t *ChatMessage) GenerateSignature() *utils.Signature {
	m, _ := json.Marshal(t)
	h := sha256.Sum256([]byte(m))
	r, s, _ := ecdsa.Sign(rand.Reader, t.senderPrivateKey, h[:])
	return &utils.Signature{R: r, S: s}
}


func (t *ChatMessage) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Sender    string `json:"sender_blockchain_address"`
		Recipient string `json:"recipient_blockchain_address"`
		Chat      string `json:"chat"`
	}{
		Sender:    t.senderBlockchainAddress,
		Recipient: t.recipientBlockchainAddress,
		Chat:      t.chat,
	})
}


type ChatRequest struct {
	SenderPrivateKey           *string `json:"sender_private_key"`
	SenderBlockchainAddress    *string `json:"sender_blockchain_address"`
	RecipientBlockchainAddress *string `json:"recipient_blockchain_address"`
	SenderPublicKey            *string `json:"sender_public_key"`
	Chat                       *string `json:"chat"`
}


//returns if chatrequest is valid
func (tr *ChatRequest) Validate() bool {
	if tr.SenderPrivateKey == nil ||
		tr.SenderBlockchainAddress == nil ||
		tr.RecipientBlockchainAddress == nil ||
		tr.SenderPublicKey == nil ||
		tr.Chat == nil {
		return false
	}
	return true
}
