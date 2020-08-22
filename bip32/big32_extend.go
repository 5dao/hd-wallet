package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
)

const (
	maxUint8 = 1<<8 - 1
)

// NewMasterKeyWithVersion creates a new master extended key from a seed
func NewMasterKeyWithVersion(seed []byte, Version []byte) (*Key, error) {
	// Generate key and chaincode
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	intermediary := hmac.Sum(nil)

	// Split it into our key and chain code
	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	err = validatePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	// Create the key struct
	key := &Key{
		Version:     Version,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}

	return key, nil
}

// Child derives a child key from a given parent as outlined by bip32
func (key *Key) Child(childIdx uint32) (*Key, error) {
	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && childIdx >= FirstHardenedChild {
		return nil, ErrHardnedChildPublicKey
	}

	intermediary, err := key.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &Key{
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
	}

	// Bip32 CKDpriv
	if key.IsPrivate {
		childKey.Version = key.Version
		fingerprint, err := hash160(publicKeyForPrivateKey(key.Key))
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = addPrivateKeys(intermediary[:32], key.Key)

		// Validate key
		err = validatePrivateKey(childKey.Key)
		if err != nil {
			return nil, err
		}
		// Bip32 CKDpub
	} else {
		keyBytes := publicKeyForPrivateKey(intermediary[:32])

		// Validate key
		err := validateChildPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		childKey.Version = key.Version
		fingerprint, err := hash160(key.Key)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = addPublicKeys(keyBytes, key.Key)
	}

	return childKey, nil
}
