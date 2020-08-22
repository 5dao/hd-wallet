//Package main
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/5dao/hd/bip32"
	"github.com/5dao/hd/bip39"
	"github.com/5dao/hd/bip44"
	"github.com/5dao/hd/coins/eth"
)

//main main
func main() {
	Bip44()
}

// Bip39 Bip39
func Bip39() {
	entropy, _ := bip39.NewEntropy(256) //128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	fmt.Println(string(mnemonic))

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

	masterKey, _ := bip32.NewMasterKey(seed)
	publicKey := masterKey.PublicKey()

	fmt.Println(publicKey)

}

// Bip44 Bip44
func Bip44() {
	mnemonic := "brand plastic task evidence thunder field deer inherit stomach shine love shuffle alter glue jelly produce aunt club habit load source globe educate shell"
	seed := bip39.NewSeed(mnemonic, "1234567")
	fmt.Println("seed", hex.EncodeToString(seed))

	accountKey, err := bip44.PathAccount(seed, "m/44'/60'/0'/0/0")
	if err != nil {
		fmt.Printf("PathAccount: %v", err)
		return
	}
	fmt.Println("account[0]", accountKey.String())

	change0, _ := accountKey.Child(0)
	fmt.Println("chang0", change0.String())

	addr0, _ := change0.Child(0)
	fmt.Println("addr0 pirvate", hex.EncodeToString(addr0.Key))
	fmt.Println("addr0 pub", hex.EncodeToString(addr0.PublicKey().Key))
	fmt.Println("addr0 addr", eth.Key2Addr(addr0.Key))
}
