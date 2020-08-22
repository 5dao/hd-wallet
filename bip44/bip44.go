package bip44

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/5dao/hd/bip32"
)

// m / purpose'/ coin'/ account'/ change / address_index

const (
	// HardenedKeyStart is the index at which a hardended key starts.  Each
	// extended key has 2^31 normal child keys and 2^31 hardned child keys.
	// Thus the range for normal child keys is [0, 2^31 - 1] and the range
	// for hardened child keys is [2^31, 2^32 - 1].
	HardenedKeyStart = 0x80000000 // 2^31

	//

)

//
var (
	HDPrivateKeyID = [4]byte{0x04, 0x88, 0xad, 0xe4}
	HDPublicKeyID  = [4]byte{0x04, 0x88, 0xb2, 0x1e}
)

// PathCoin m/purpose'/coin'
func PathCoin(seed []byte, path string) (key *bip32.Key, err error) {
	path = strings.ReplaceAll(path, "'", "")

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 3 {
		err = fmt.Errorf("m/purpose'/coin'/")
		return
	}

	if pathParts[0] != "m" {
		err = fmt.Errorf("path[0]!=m")
		return
	}

	if pathParts[1] != "44" {
		err = fmt.Errorf("path[1]!=44")
		return
	}

	var coinIndex uint64
	coinIndex, err = strconv.ParseUint(pathParts[2], 10, 32)
	if err != nil {
		err = fmt.Errorf("coinIndex: %v", err)
		return
	}

	// See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	var ext *bip32.Key
	if ext, err = bip32.NewMasterKeyWithVersion(seed, HDPrivateKeyID[:]); err != nil {
		err = fmt.Errorf("NewMasterKeyWithVersion: %v", err)
		return
	}
	// fmt.Println("masterKey(BIP32 Root Key)", ext.String())

	// m/44'

	// Child returns a derived child extended key at the given index.  When this
	// extended key is a private extended key (as determined by the IsPrivate
	// function), a private extended key will be derived.  Otherwise, the derived
	// extended key will be also be a public extended key.
	var purpose *bip32.Key
	if purpose, err = ext.Child(44 + HardenedKeyStart); err != nil {
		err = fmt.Errorf("purpose: %v", err)
		return
	}

	// m/44'/coin'
	var coinKey *bip32.Key
	if coinKey, err = purpose.Child(uint32(coinIndex) + HardenedKeyStart); err != nil {
		err = fmt.Errorf("coinKey: %v", err)
		return
	}
	key = coinKey

	return
}

// PathAccount m/purpose'/coin'/account'
func PathAccount(seed []byte, path string) (key *bip32.Key, err error) {
	var coinKey *bip32.Key
	if coinKey, err = PathCoin(seed, path); err != nil {
		return
	}

	path = strings.ReplaceAll(path, "'", "")
	pathParts := strings.Split(path, "/")
	if len(pathParts) < 4 {
		err = fmt.Errorf("m/purpose'/coin'/account'")
		return
	}

	var accountIndex uint64
	accountIndex, err = strconv.ParseUint(pathParts[3], 10, 32)
	if err != nil {
		err = fmt.Errorf("accountIndex: %v", err)
		return
	}

	// m/44'/coin'/account'/
	var accountKey *bip32.Key
	if accountKey, err = coinKey.Child(uint32(accountIndex) + HardenedKeyStart); err != nil {
		err = fmt.Errorf("accountKey: %v", err)
		return
	}

	key = accountKey

	return
}

// PathChange m/purpose'/coin'/account'/change
func PathChange(seed []byte, path string) (key *bip32.Key, err error) {
	var accountKey *bip32.Key
	if accountKey, err = PathAccount(seed, path); err != nil {
		return
	}

	path = strings.ReplaceAll(path, "'", "")
	pathParts := strings.Split(path, "/")
	if len(pathParts) < 5 {
		err = fmt.Errorf("m/purpose'/coin'/account'/change")
		return
	}

	var changeIndex uint64
	if changeIndex, err = strconv.ParseUint(pathParts[4], 10, 32); err != nil {
		err = fmt.Errorf("changeIndex: %v", err)
		return
	}

	// m/44'/coin'/account'/change
	if key, err = accountKey.Child(uint32(changeIndex)); err != nil {
		err = fmt.Errorf("changeKey: %v", err)
		return
	}
	return
}

// PathAddr  m/purpose'/coin'/account'/change/address_index
func PathAddr(seed []byte, path string) (addresskey *bip32.Key, err error) {
	var changeKey *bip32.Key
	if changeKey, err = PathChange(seed, path); err != nil {
		return
	}

	var pathParts []string
	if pathParts := strings.Split(strings.ReplaceAll(path, "'", ""), "/"); len(pathParts) != 6 {
		err = fmt.Errorf("m/purpose'/coin'/account'/change/address_index")
		return
	}

	var addressIndex uint64
	if addressIndex, err = strconv.ParseUint(pathParts[5], 10, 32); err != nil {
		err = fmt.Errorf("addressIndex: %v", err)
		return
	}

	// // m/44'/coin'/account'/change/addrIndex
	if addresskey, err = changeKey.Child(uint32(addressIndex)); err != nil {
		err = fmt.Errorf("addresskey: %v", err)
		return
	}
	return
}
