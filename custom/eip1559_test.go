package custom

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"testing"
)

func sendTransfer(config params.ChainConfig, chainInfo params.ChainInfo) {
	client, err := ethclient.Dial(chainInfo.RpcUrl)
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
		log.Fatal("Unable to get nonce", err)
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

	cfg, block := &config, config.LondonBlock
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
	fmt.Println("Tx send, view on explorer: " + chainInfo.ExplorerUrl + "tx/" + signedTx.Hash().Hex())
}

func sendTokenTransfer(config params.ChainConfig, chainInfo params.ChainInfo, amount string, tokenContractAddress string) {
	client, err := ethclient.Dial(chainInfo.RpcUrl)
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
		log.Fatal("Unable to get nonce ", err)
	}
	fmt.Println("Nonce:", nonce)
	toAddress := common.HexToAddress("0x409294dF5a810bdF2dA4b053a5f9d5EfB2D53f16")
	tokenAddress := common.HexToAddress(tokenContractAddress)
	value := big.NewInt(0)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println("Method Id: " + hexutil.Encode(methodID)) // 0xa9059cbb

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Println("Token Address: " + hexutil.Encode(paddedAddress))

	amountInt := new(big.Int)
	amountInt.SetString(amount, 10)
	paddedAmount := common.LeftPadBytes(amountInt.Bytes(), 32)
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
	cfg, block := &config, config.LondonBlock
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
		log.Fatal("Unable to send transaction ", err)
	}
	fmt.Println("Tx send, view on explorer: " + chainInfo.ExplorerUrl + "tx/" + signedTx.Hash().Hex())
}

func TestPolygonTransfer(t *testing.T) {
	sendTransfer(*params.MumbaiChainConfig, *params.MumbaiChainInfo)
}

func TestPolygonTokenTransfer(t *testing.T) {
	sendTokenTransfer(*params.MumbaiChainConfig, *params.MumbaiChainInfo, "10000000000000000", "0x326c977e6efc84e512bb9c30f76e30c160ed06fb")
}

func TestETHTransfer(t *testing.T) {
	sendTransfer(*params.RopstenChainConfig, *params.RopstenChainInfo)
}

func TestETHTokenTransfer(t *testing.T) {
	sendTokenTransfer(*params.RopstenChainConfig, *params.RopstenChainInfo, "1000000000000000000", "0x91565011007d12Bd0970d72f96e83224FDDeCb73")
}

func TestMoonTransfer(t *testing.T) {
	sendTransfer(*params.MoonChainConfig, *params.MoonChainInfo)
}
