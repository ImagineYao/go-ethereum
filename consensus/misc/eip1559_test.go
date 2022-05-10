// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package misc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// copyConfig does a _shallow_ copy of a given config. Safe to set new values, but
// do not use e.g. SetInt() on the numbers. For testing only
func copyConfig(original *params.ChainConfig) *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:                 original.ChainID,
		HomesteadBlock:          original.HomesteadBlock,
		DAOForkBlock:            original.DAOForkBlock,
		DAOForkSupport:          original.DAOForkSupport,
		EIP150Block:             original.EIP150Block,
		EIP150Hash:              original.EIP150Hash,
		EIP155Block:             original.EIP155Block,
		EIP158Block:             original.EIP158Block,
		ByzantiumBlock:          original.ByzantiumBlock,
		ConstantinopleBlock:     original.ConstantinopleBlock,
		PetersburgBlock:         original.PetersburgBlock,
		IstanbulBlock:           original.IstanbulBlock,
		MuirGlacierBlock:        original.MuirGlacierBlock,
		BerlinBlock:             original.BerlinBlock,
		LondonBlock:             original.LondonBlock,
		TerminalTotalDifficulty: original.TerminalTotalDifficulty,
		Ethash:                  original.Ethash,
		Clique:                  original.Clique,
	}
}

func config() *params.ChainConfig {
	config := copyConfig(params.TestChainConfig)
	config.LondonBlock = big.NewInt(5)
	return config
}

// TestBlockGasLimits tests the gasLimit checks for blocks both across
// the EIP-1559 boundary and post-1559 blocks
func TestBlockGasLimits(t *testing.T) {
	initial := new(big.Int).SetUint64(params.InitialBaseFee)

	for i, tc := range []struct {
		pGasLimit uint64
		pNum      int64
		gasLimit  uint64
		ok        bool
	}{
		// Transitions from non-london to london
		{10000000, 4, 20000000, true},  // No change
		{10000000, 4, 20019530, true},  // Upper limit
		{10000000, 4, 20019531, false}, // Upper +1
		{10000000, 4, 19980470, true},  // Lower limit
		{10000000, 4, 19980469, false}, // Lower limit -1
		// London to London
		{20000000, 5, 20000000, true},
		{20000000, 5, 20019530, true},  // Upper limit
		{20000000, 5, 20019531, false}, // Upper limit +1
		{20000000, 5, 19980470, true},  // Lower limit
		{20000000, 5, 19980469, false}, // Lower limit -1
		{40000000, 5, 40039061, true},  // Upper limit
		{40000000, 5, 40039062, false}, // Upper limit +1
		{40000000, 5, 39960939, true},  // lower limit
		{40000000, 5, 39960938, false}, // Lower limit -1
	} {
		parent := &types.Header{
			GasUsed:  tc.pGasLimit / 2,
			GasLimit: tc.pGasLimit,
			BaseFee:  initial,
			Number:   big.NewInt(tc.pNum),
		}
		header := &types.Header{
			GasUsed:  tc.gasLimit / 2,
			GasLimit: tc.gasLimit,
			BaseFee:  initial,
			Number:   big.NewInt(tc.pNum + 1),
		}
		err := VerifyEip1559Header(config(), parent, header)
		if tc.ok && err != nil {
			t.Errorf("test %d: Expected valid header: %s", i, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("test %d: Expected invalid header", i)
		}
	}
}

// TestCalcBaseFee assumes all blocks are 1559-blocks
func TestCalcBaseFee(t *testing.T) {
	tests := []struct {
		parentBaseFee   int64
		parentGasLimit  uint64
		parentGasUsed   uint64
		expectedBaseFee int64
	}{
		{params.InitialBaseFee, 20000000, 10000000, params.InitialBaseFee}, // usage == target
		{params.InitialBaseFee, 20000000, 9000000, 987500000},              // usage below target
		{params.InitialBaseFee, 20000000, 11000000, 1012500000},            // usage above target
	}
	for i, test := range tests {
		parent := &types.Header{
			Number:   common.Big32,
			GasLimit: test.parentGasLimit,
			GasUsed:  test.parentGasUsed,
			BaseFee:  big.NewInt(test.parentBaseFee),
		}
		if have, want := CalcBaseFee(config(), parent), big.NewInt(test.expectedBaseFee); have.Cmp(want) != 0 {
			t.Errorf("test %d: have %d  want %d, ", i, have, want)
		}
	}
}

func TestETHTransfer(t *testing.T) {
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161")
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := crypto.HexToECDSA("4b162c7a41d8935b8ca700fb314f0f32f4ab13989e6e73b544b4ed1bd5fb8639")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Unable to cast")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	address := hex.EncodeToString(fromAddress[:])
	fmt.Println("Address: 0x" + address)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal("Unable to get nonce")
	}
	fmt.Println("Nonce:", nonce)
	toAddress := common.HexToAddress("0x409294dF5a810bdF2dA4b053a5f9d5EfB2D53f16")
	value := big.NewInt(10000000000000000)

	gasLimit := uint64(21000)
	gasTipCap, _ := client.SuggestGasTipCap(context.Background())
	gasFeeCap, _ := client.SuggestGasPrice(context.Background())
	fmt.Println("Gas Tip Cap: " + gasTipCap.String())
	fmt.Println("Gas Price: " + gasFeeCap.String())

	var data []byte

	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     value,
		Data:      data,
	})

	cfg, block := params.RopstenChainConfig, params.RopstenChainConfig.LondonBlock
	signer := types.MakeSigner(cfg, block)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		log.Fatal("Unable to sign Tx\n", err)
	}

	hash := signedTx.Hash().Bytes()

	raw, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		log.Fatal("Unable to cast to raw txn")
	}

	fmt.Printf("Hash: %x\n%x\n", hash, raw)

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal("Unable to send transaction", err)
	}
	fmt.Printf("Tx send: %s", signedTx.Hash().Hex())
}

func TestETHTokenTransfer(t *testing.T) {
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161")
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := crypto.HexToECDSA("4b162c7a41d8935b8ca700fb314f0f32f4ab13989e6e73b544b4ed1bd5fb8639")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Unable to cast")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	address := hexutil.Encode(fromAddress[:])
	fmt.Println("Address: " + address)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal("Unable to get nonce")
	}
	fmt.Println("Nonce:", nonce)
	toAddress := common.HexToAddress("0x409294dF5a810bdF2dA4b053a5f9d5EfB2D53f16")
	tokenAddress := common.HexToAddress("0x91565011007d12bd0970d72f96e83224fddecb73")
	value := big.NewInt(0)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println("Method Id: " + hexutil.Encode(methodID)) // 0xa9059cbb

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Println("Token Address: " + hexutil.Encode(paddedAddress))

	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10)
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Println("Hex Amount: " + hexutil.Encode(paddedAmount))

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	gasTipCap, _ := client.SuggestGasTipCap(context.Background())
	gasFeeCap, _ := client.SuggestGasPrice(context.Background())
	fmt.Println("Gas Tip Cap: " + gasTipCap.String())
	fmt.Println("Gas Price: " + gasFeeCap.String())

	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Gas:       uint64(80000),
		To:        &tokenAddress,
		Value:     value,
		Data:      data,
	})
	cfg, block := params.RopstenChainConfig, params.RopstenChainConfig.LondonBlock
	signer := types.MakeSigner(cfg, block)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		log.Fatal("Unable to sign Tx\n", err)
	}

	txHash := signedTx.Hash().Bytes()

	raw, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		log.Fatal("Unable to cast to raw txn")
	}

	fmt.Printf("Tx Hash: %x\n", txHash)

	fmt.Printf("Raw Tx: %x\n", raw)

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal("Unable to send transaction", err)
	}
	fmt.Println("Tx send, view on explorer: https://ropsten.etherscan.io/tx/" + signedTx.Hash().Hex())
}
