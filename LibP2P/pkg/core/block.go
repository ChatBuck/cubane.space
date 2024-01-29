package core

import (
	"github.com/KhetwalDevesh/golang-cubane/pkg/types"
)

type Header struct {
	Version   uint32
	PrevBlock types.Hash
	Timestamp int64
	Height    uint32
	Nonce     uint64
}

type Block struct {
	Header
	Transactions []Transaction
}
