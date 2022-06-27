package params

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type ChainInfo struct {
	RpcUrl      string
	ExplorerUrl string
}

var (
	RopstenChainInfo = &ChainInfo{
		RpcUrl:      "https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
		ExplorerUrl: "https://ropsten.etherscan.io/",
	}

	// MumbaiChainConfig is the chain parameters to run a node on the polygon test network
	MumbaiChainConfig = &ChainConfig{
		ChainID:             big.NewInt(80001),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.HexToHash("0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d"),
		EIP155Block:         big.NewInt(10),
		EIP158Block:         big.NewInt(10),
		ByzantiumBlock:      big.NewInt(1_700_000),
		ConstantinopleBlock: big.NewInt(4_230_000),
		PetersburgBlock:     big.NewInt(4_939_394),
		IstanbulBlock:       big.NewInt(6_485_846),
		MuirGlacierBlock:    big.NewInt(7_117_117),
		BerlinBlock:         big.NewInt(9_812_189),
		LondonBlock:         big.NewInt(10_499_401),
		Ethash:              new(EthashConfig),
	}
	MumbaiChainInfo = &ChainInfo{
		RpcUrl:      "https://rpc-mumbai.matic.today/",
		ExplorerUrl: "https://mumbai.polygonscan.com/",
	}

	// MoonChainConfig is the chain parameters to run a node on the moonbase alpha test network
	MoonChainConfig = &ChainConfig{
		ChainID:             big.NewInt(1287),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.HexToHash("0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d"),
		EIP155Block:         big.NewInt(10),
		EIP158Block:         big.NewInt(10),
		ByzantiumBlock:      big.NewInt(1_700_000),
		ConstantinopleBlock: big.NewInt(4_230_000),
		PetersburgBlock:     big.NewInt(4_939_394),
		IstanbulBlock:       big.NewInt(6_485_846),
		MuirGlacierBlock:    big.NewInt(7_117_117),
		BerlinBlock:         big.NewInt(9_812_189),
		LondonBlock:         big.NewInt(10_499_401),
		Ethash:              new(EthashConfig),
	}
	MoonChainInfo = &ChainInfo{
		RpcUrl:      "https://rpc.api.moonbase.moonbeam.network",
		ExplorerUrl: "https://moonbase.moonscan.io/",
	}
)
