//Package eth hd
package eth

import (
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/5dao/hd/util"
)

// Key2Addr Key2Addr
func Key2Addr(key []byte) (address string) {
	_, pubk := util.ECDAOfSecp256k1(key)
	addr := crypto.PubkeyToAddress(pubk)
	address = addr.String()
	return
}
