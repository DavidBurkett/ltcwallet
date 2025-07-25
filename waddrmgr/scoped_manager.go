package waddrmgr

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/ltcsuite/ltcd/btcec/v2"
	"github.com/ltcsuite/ltcd/btcec/v2/schnorr"
	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/hdkeychain"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/ltcwallet/internal/zero"
	"github.com/ltcsuite/ltcwallet/netparams"
	"github.com/ltcsuite/ltcwallet/walletdb"
	"github.com/ltcsuite/neutrino/cache/lru"
)

// HDVersion represents the different supported schemes of hierarchical
// derivation.
// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0132.md#registered-hd-version-bytes
type HDVersion uint32

const (
	// HDVersionMainNetBIP0044 is the HDVersion for BIP-0044 on the main
	// network.
	HDVersionMainNetBIP0044 HDVersion = 0x0488b21e // xpub

	// HDVersionMainNetBIP0049 is the HDVersion for BIP-0049 on the main
	// network.
	HDVersionMainNetBIP0049 HDVersion = 0x049d7cb2 // ypub

	// HDVersionMainNetBIP0084 is the HDVersion for BIP-0084 on the main
	// network.
	HDVersionMainNetBIP0084 HDVersion = 0x04b24746 // zpub

	// HDVersionTestNetBIP0044 is the HDVersion for BIP-0044 on the test
	// network.
	HDVersionTestNetBIP0044 HDVersion = 0x043587cf // tpub

	// HDVersionTestNetBIP0049 is the HDVersion for BIP-0049 on the test
	// network.
	HDVersionTestNetBIP0049 HDVersion = 0x044a5262 // upub

	// HDVersionTestNetBIP0084 is the HDVersion for BIP-0084 on the test
	// network.
	HDVersionTestNetBIP0084 HDVersion = 0x045f1cf6 // vpub

	// HDVersionSimNetBIP0044 is the HDVersion for BIP-0044 on the
	// simulation test network. There aren't any other versions defined for
	// the simulation test network.
	HDVersionSimNetBIP0044 HDVersion = 0x0420bd3a // spub
)

const (
	// defaultPrivKeyCacheSize is the default size of the LRU cache that
	// we'll use to cache private keys to avoid DB and EC operations within
	// the wallet. With the default sisize, we'll allocate up to 320 KB to
	// caching private keys (ignoring pointer overhead, etc).
	defaultPrivKeyCacheSize = 10_000
)

// DerivationPath represents a derivation path from a particular key manager's
// scope.  Each ScopedKeyManager starts key derivation from the end of their
// cointype hardened key: m/purpose'/cointype'. The fields in this struct allow
// further derivation to the next three child levels after the coin type key.
// This restriction is in the spriti of BIP0044 type derivation. We maintain a
// degree of coherency with the standard, but allow arbitrary derivations
// beyond the cointype key. The key derived using this path will be exactly:
// m/purpose'/cointype'/account/branch/index, where purpose' and cointype' are
// bound by the scope of a particular manager.
type DerivationPath struct {
	// InternalAccount is the internal account number used within the
	// wallet's database to identify accounts.
	InternalAccount uint32

	// Account is the account, or the first immediate child from the scoped
	// manager's hardened coin type key.
	Account uint32

	// Branch is the branch to be derived from the account index above. For
	// BIP0044-like derivation, this is either 0 (external) or 1
	// (internal). However, we allow this value to vary arbitrarily within
	// its size range.
	Branch uint32

	// Index is the final child in the derivation path. This denotes the
	// key index within as a child of the account and branch.
	Index uint32

	// MasterKeyFingerprint represents the fingerprint of the root key (also
	// known as the key with derivation path m/) corresponding to the
	// account public key. This may be required by some hardware wallets for
	// proper identification and signing.
	MasterKeyFingerprint uint32
}

// KeyScope represents a restricted key scope from the primary root key within
// the HD chain. From the root manager (m/) we can create a nearly arbitrary
// number of ScopedKeyManagers of key derivation path: m/purpose'/cointype'.
// These scoped managers can then me managed indecently, as they house the
// encrypted cointype key and can derive any child keys from there on.
type KeyScope struct {
	// Purpose is the purpose of this key scope. This is the first child of
	// the master HD key.
	Purpose uint32

	// Coin is a value that represents the particular coin which is the
	// child of the purpose key. With this key, any accounts, or other
	// children can be derived at all.
	Coin uint32
}

// ScopedIndex is a tuple of KeyScope and child Index. This is used to compactly
// identify a particular child key, when the account and branch can be inferred
// from context.
type ScopedIndex struct {
	// Scope is the BIP44 account' used to derive the child key.
	Scope KeyScope

	// Index is the BIP44 address_index used to derive the child key.
	Index uint32
}

// String returns a human readable version describing the keypath encapsulated
// by the target key scope.
func (k KeyScope) String() string {
	return fmt.Sprintf("m/%v'/%v'", k.Purpose, k.Coin)
}

// Identity is a closure that returns the identifier of an address.
type Identity func() []byte

// ScriptHashIdentity returns the identity closure for a p2sh script.
func ScriptHashIdentity(script []byte) Identity {
	return func() []byte {
		return ltcutil.Hash160(script)
	}
}

// WitnessScriptHashIdentity returns the identity closure for a p2wsh script.
func WitnessScriptHashIdentity(script []byte) Identity {
	return func() []byte {
		digest := sha256.Sum256(script)
		return digest[:]
	}
}

// TaprootIdentity returns the identity closure for a p2tr script.
func TaprootIdentity(taprootKey *btcec.PublicKey) Identity {
	return func() []byte {
		return schnorr.SerializePubKey(taprootKey)
	}
}

// ScopeAddrSchema is the address schema of a particular KeyScope. This will be
// persisted within the database, and will be consulted when deriving any keys
// for a particular scope to know how to encode the public keys as addresses.
type ScopeAddrSchema struct {
	// ExternalAddrType is the address type for all keys within branch 0.
	ExternalAddrType AddressType

	// InternalAddrType is the address type for all keys within branch 1
	// (change addresses).
	InternalAddrType AddressType
}

var (
	// KeyScopeBIP0049Plus is the key scope of our modified BIP0049
	// derivation. We say this is BIP0049 "plus", as we'll actually use
	// p2wkh change all change addresses.
	KeyScopeBIP0049Plus = KeyScope{
		Purpose: 49,
		Coin:    2,
	}

	// KeyScopeBIP0084 is the key scope for BIP0084 derivation. BIP0084
	// will be used to derive all p2wkh addresses.
	KeyScopeBIP0084 = KeyScope{
		Purpose: 84,
		Coin:    2,
	}

	// KeyScopeBIP0086 is the key scope for BIP0086 derivation. BIP0086
	// will be used to derive all p2tr addresses.
	KeyScopeBIP0086 = KeyScope{
		Purpose: 86,
		Coin:    2,
	}

	// KeyScopeBIP0044 is the key scope for BIP0044 derivation. Legacy
	// wallets will only be able to use this key scope, and no keys beyond
	// it.
	KeyScopeBIP0044 = KeyScope{
		Purpose: 44,
		Coin:    2,
	}

	// KeyScopeMweb is the key scope for MWEB derivation.
	KeyScopeMweb = KeyScope{
		Purpose: 1000,
		Coin:    2,
	}

	// KeyScopeLiteWallet is the key scope for LiteWallet derivation.
	KeyScopeLiteWallet = KeyScope{
		Purpose: 9999,
		Coin:    2,
	}

	// DefaultKeyScopes is the set of default key scopes that will be
	// created by the root manager upon initial creation.
	DefaultKeyScopes = []KeyScope{
		KeyScopeBIP0049Plus,
		KeyScopeBIP0084,
		KeyScopeBIP0086,
		KeyScopeBIP0044,
		KeyScopeMweb,
		KeyScopeLiteWallet,
	}

	// ScopeAddrMap is a map from the default key scopes to the scope
	// address schema for each scope type. This will be consulted during
	// the initial creation of the root key manager.
	ScopeAddrMap = map[KeyScope]ScopeAddrSchema{
		KeyScopeBIP0049Plus: {
			ExternalAddrType: NestedWitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0084: {
			ExternalAddrType: WitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0086: {
			ExternalAddrType: TaprootPubKey,
			InternalAddrType: TaprootPubKey,
		},
		KeyScopeBIP0044: {
			InternalAddrType: PubKeyHash,
			ExternalAddrType: PubKeyHash,
		},
		KeyScopeMweb: {
			InternalAddrType: Mweb,
			ExternalAddrType: Mweb,
		},
		KeyScopeLiteWallet: {
			InternalAddrType: PubKeyHash,
			ExternalAddrType: PubKeyHash,
		},
	}

	// KeyScopeBIP0049AddrSchema is the address schema for the traditional
	// BIP-0049 derivation scheme. This exists in order to support importing
	// accounts from other wallets that don't use our modified BIP-0049
	// derivation scheme (internal addresses are P2WKH instead of NP2WKH).
	KeyScopeBIP0049AddrSchema = ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: NestedWitnessPubKey,
	}

	// ImportedDerivationPath is the derivation path for an imported
	// address. The Account, Branch, and Index members are not known, so
	// they are left blank.
	ImportedDerivationPath = DerivationPath{
		InternalAccount: ImportedAddrAccount,
	}
)

// IsDefaultScope return true if the given scope belongs to the list of default
// scopes.
func IsDefaultScope(scope KeyScope) bool {
	for _, defaultScope := range DefaultKeyScopes {
		if defaultScope == scope {
			return true
		}
	}

	return false
}

// ScopedKeyManager is a sub key manager under the main root key manager. The
// root key manager will handle the root HD key (m/), while each sub scoped key
// manager will handle the cointype key for a particular key scope
// (m/purpose'/cointype'). This abstraction allows higher-level applications
// built upon the root key manager to perform their own arbitrary key
// derivation, while still being protected under the encryption of the root key
// manager.
type ScopedKeyManager struct {
	// scope is the scope of this key manager. We can only generate keys
	// that are direct children of this scope.
	scope KeyScope

	// addrSchema is the address schema for this sub manager. This will be
	// consulted when encoding addresses from derived keys.
	addrSchema ScopeAddrSchema

	// rootManager is a pointer to the root key manager. We'll maintain
	// this as we need access to the crypto encryption keys before we can
	// derive any new accounts of child keys of accounts.
	rootManager *Manager

	// addrs is a cached map of all the addresses that we currently
	// manage.
	addrs map[addrKey]ManagedAddress

	// acctInfo houses information about accounts including what is needed
	// to generate deterministic chained keys for each created account.
	acctInfo map[uint32]*accountInfo

	// deriveOnUnlock is a list of private keys which needs to be derived
	// on the next unlock.  This occurs when a public address is derived
	// while the address manager is locked since it does not have access to
	// the private extended key (hence nor the underlying private key) in
	// order to encrypt it.
	deriveOnUnlock []*unlockDeriveInfo

	// privKeyCache stores the set of private keys that have been marked as
	// items to be cached to allow us to avoid the database and EC
	// operations each time a key need to be obtained.
	privKeyCache *lru.Cache[DerivationPath, *cachedKey]

	mtx sync.RWMutex
}

// Scope returns the exact KeyScope of this scoped key manager.
func (s *ScopedKeyManager) Scope() KeyScope {
	return s.scope
}

// AddrSchema returns the set address schema for the target ScopedKeyManager.
func (s *ScopedKeyManager) AddrSchema() ScopeAddrSchema {
	return s.addrSchema
}

// zeroSensitivePublicData performs a best try effort to remove and zero all
// sensitive public data associated with the address manager such as
// hierarchical deterministic extended public keys and the crypto public keys.
func (s *ScopedKeyManager) zeroSensitivePublicData() {
	// Clear all of the account private keys.
	for _, acctInfo := range s.acctInfo {
		acctInfo.acctKeyPub.Zero()
		acctInfo.acctKeyPub = nil
	}
}

// Close cleanly shuts down the manager.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address manager from memory.
func (s *ScopedKeyManager) Close() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Attempt to clear sensitive public key material from memory too.
	s.zeroSensitivePublicData()
}

// keyToManaged returns a new managed address for the provided derived key and
// its derivation path which consists of the account, branch, and index.
//
// The passed derivedKey is zeroed after the new address is created.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) keyToManaged(derivedKey *hdkeychain.ExtendedKey,
	derivationPath DerivationPath, acctInfo *accountInfo) (
	ManagedAddress, error) {

	// Choose the appropriate type of address to derive since it's possible
	// for a watch-only account to have a different schema from the
	// manager's.
	internal := derivationPath.Branch == InternalBranch
	addrType := s.accountAddrType(acctInfo, internal)

	// Create a new managed address based on the public or private key
	// depending on whether the passed key is private.  Also, zero the key
	// after creating the managed address from it.
	ma, err := newManagedAddressFromExtKey(
		s, derivationPath, derivedKey, addrType, acctInfo,
	)
	defer derivedKey.Zero()
	if err != nil {
		return nil, err
	}

	if !derivedKey.IsPrivate() {
		// Add the managed address to the list of addresses that need
		// their private keys derived when the address manager is next
		// unlocked.
		info := unlockDeriveInfo{
			managedAddr: ma,
			branch:      derivationPath.Branch,
			index:       derivationPath.Index,
		}
		s.deriveOnUnlock = append(s.deriveOnUnlock, &info)
	}

	if derivationPath.Branch == InternalBranch {
		ma.internal = true
	}

	return ma, nil
}

// deriveKey returns either a public or private derived extended key based on
// the private flag for the given an account info, branch, and index.
func (s *ScopedKeyManager) deriveKey(acctInfo *accountInfo, branch,
	index uint32, private bool) (*hdkeychain.ExtendedKey, error) {

	// Choose the public or private extended key based on whether or not
	// the private flag was specified.  This, in turn, allows for public or
	// private child derivation.
	acctKey := acctInfo.acctKeyPub
	if private {
		acctKey = acctInfo.acctKeyPriv
	}

	if acctInfo.scanKey != nil {
		return s.deriveSpendKey(acctKey, acctInfo, index)
	}

	// Derive and return the key.
	branchKey, err := acctKey.DeriveNonStandard(branch) // nolint:staticcheck
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branch)
		return nil, managerError(ErrKeyChain, str, err)
	}

	addressKey, err := branchKey.DeriveNonStandard(index) // nolint:staticcheck

	// Zero branch key after it's used.
	branchKey.Zero()
	if err != nil {
		str := fmt.Sprintf("failed to derive child extended key -- "+
			"branch %d, child %d",
			branch, index)
		return nil, managerError(ErrKeyChain, str, err)
	}

	return addressKey, nil
}

// deriveSpendKey returns either a public or private derived MWEB spend key
// for the given extended key, account info, and index.
func (s *ScopedKeyManager) deriveSpendKey(key *hdkeychain.ExtendedKey,
	acctInfo *accountInfo, index uint32) (*hdkeychain.ExtendedKey, error) {

	scanKeyPriv, _ := acctInfo.scanKey.ECPrivKey()
	defer scanKeyPriv.Zero()
	scanSecret := mw.SecretKey(scanKeyPriv.Key.Bytes())
	defer zero.Bytes(scanSecret[:])

	var keyBytes []byte
	if key.IsPrivate() {
		spendKey, err := key.Derive(hdkeychain.HardenedKeyStart + 1)
		if err != nil {
			str := "failed to derive spend key"
			return nil, managerError(ErrKeyChain, str, err)
		}
		defer spendKey.Zero() // Ensure key is zeroed when done.
		spendKeyPriv, _ := spendKey.ECPrivKey()
		defer spendKeyPriv.Zero()
		spendSecret := mw.SecretKey(spendKeyPriv.Key.Bytes())
		defer zero.Bytes(spendSecret[:])
		keychain := &mweb.Keychain{Scan: &scanSecret, Spend: &spendSecret}
		keyBytes = keychain.SpendKey(index)[:]
	} else {
		spendKeyPub, _ := acctInfo.spendPubKey.ECPubKey()
		spendPubKey := (*mw.PublicKey)(spendKeyPub.SerializeCompressed())
		keychain := &mweb.Keychain{Scan: &scanSecret, SpendPubKey: spendPubKey}
		keyBytes = keychain.Address(index).Spend[:]
	}
	return hdkeychain.NewExtendedKey(nil, keyBytes, nil, nil, 0, 0, key.IsPrivate()), nil
}

func (s *ScopedKeyManager) LoadMwebKeychain(ns walletdb.ReadBucket, account uint32) (*mweb.Keychain, error) {
	// The next address can only be generated for accounts that have
	// already been created.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	if acctInfo.scanKey == nil {
		str := "failed to derive scan key"
		return nil, managerError(ErrKeyChain, str, err)
	}

	scanKeyPriv, _ := acctInfo.scanKey.ECPrivKey()
	defer scanKeyPriv.Zero()
	scanSecret := mw.SecretKey(scanKeyPriv.Key.Bytes())

	acctKey := acctInfo.acctKeyPub
	watchOnly := s.rootManager.watchOnly() || len(acctInfo.acctKeyEncrypted) == 0
	if !s.rootManager.isLocked() && !watchOnly {
		acctKey = acctInfo.acctKeyPriv
	}

	var keychain *mweb.Keychain
	if acctKey.IsPrivate() {
		spendKey, err := acctKey.Derive(hdkeychain.HardenedKeyStart + 1)
		if err != nil {
			str := "failed to derive spend key"
			return nil, managerError(ErrKeyChain, str, err)
		}
		defer spendKey.Zero() // Ensure key is zeroed when done.
		spendKeyPriv, _ := spendKey.ECPrivKey()
		defer spendKeyPriv.Zero()
		spendSecret := mw.SecretKey(spendKeyPriv.Key.Bytes())

		keychain = &mweb.Keychain{Scan: &scanSecret, Spend: &spendSecret}
	} else {
		spendKeyPub, _ := acctInfo.spendPubKey.ECPubKey()
		spendPubKey := (*mw.PublicKey)(spendKeyPub.SerializeCompressed())
		keychain = &mweb.Keychain{Scan: &scanSecret, SpendPubKey: spendPubKey}
	}

	return keychain, nil
}

// loadAccountInfo attempts to load and cache information about the given
// account from the database.   This includes what is necessary to derive new
// keys for it and track the state of the internal and external branches.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) loadAccountInfo(ns walletdb.ReadBucket,
	account uint32) (*accountInfo, error) {

	// Return the account info from cache if it's available.
	if acctInfo, ok := s.acctInfo[account]; ok {
		return acctInfo, nil
	}

	// The account is either invalid or just wasn't cached, so attempt to
	// load the information from the database.
	rowInterface, err := fetchAccountInfo(ns, &s.scope, account)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	decryptKey := func(cryptoKey EncryptorDecryptor,
		encryptedKey []byte) (*hdkeychain.ExtendedKey, error) {

		serializedKey, err := cryptoKey.Decrypt(encryptedKey)
		if err != nil {
			return nil, err
		}
		return hdkeychain.NewKeyFromString(string(serializedKey))
	}

	// The wallet will only contain private keys for default accounts if the
	// wallet's not set up as watch-only and it's been unlocked.
	watchOnly := s.rootManager.watchOnly()
	hasPrivateKey := !s.rootManager.isLocked() && !watchOnly

	// Create the new account info with the known information. The rest of
	// the fields are filled out below.
	var acctInfo *accountInfo
	switch row := rowInterface.(type) {
	case *dbDefaultAccountRow:
		acctInfo = &accountInfo{
			acctName:          row.name,
			acctType:          row.acctType,
			acctKeyEncrypted:  row.privKeyEncrypted,
			nextExternalIndex: row.nextExternalIndex,
			nextInternalIndex: row.nextInternalIndex,
		}

		// Use the crypto public key to decrypt the account public
		// extended key.
		acctInfo.acctKeyPub, err = decryptKey(
			s.rootManager.cryptoKeyPub, row.pubKeyEncrypted,
		)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt public key for "+
				"account %d", account)
			return nil, managerError(ErrCrypto, str, err)
		}

		if hasPrivateKey {
			// Use the crypto private key to decrypt the account
			// private extended keys.
			acctInfo.acctKeyPriv, err = decryptKey(
				s.rootManager.cryptoKeyPriv, row.privKeyEncrypted,
			)
			if err != nil {
				str := fmt.Sprintf("failed to decrypt private "+
					"key for account %d", account)
				return nil, managerError(ErrCrypto, str, err)
			}
		}

		// Use the crypto public key to decrypt the account
		// scan key and spend pubkey.
		if len(row.scanKeyEncrypted) > 0 {
			acctInfo.scanKey, err = decryptKey(
				s.rootManager.cryptoKeyPub, row.scanKeyEncrypted,
			)
			if err != nil {
				str := fmt.Sprintf("failed to decrypt scan key "+
					"for account %d", account)
				return nil, managerError(ErrCrypto, str, err)
			}

			acctInfo.spendPubKey, err = decryptKey(
				s.rootManager.cryptoKeyPub, row.spendPubKeyEncrypted,
			)
			if err != nil {
				str := fmt.Sprintf("failed to decrypt spend key "+
					"for account %d", account)
				return nil, managerError(ErrCrypto, str, err)
			}
		}

	case *dbWatchOnlyAccountRow:
		acctInfo = &accountInfo{
			acctName:             row.name,
			acctType:             row.acctType,
			nextExternalIndex:    row.nextExternalIndex,
			nextInternalIndex:    row.nextInternalIndex,
			addrSchema:           row.addrSchema,
			masterKeyFingerprint: row.masterKeyFingerprint,
		}

		// Use the crypto public key to decrypt the account public
		// extended key.
		acctInfo.acctKeyPub, err = decryptKey(
			s.rootManager.cryptoKeyPub, row.pubKeyEncrypted,
		)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt public key for "+
				"account %d", account)
			return nil, managerError(ErrCrypto, str, err)
		}

		hasPrivateKey = false

	default:
		str := fmt.Sprintf("unsupported account type %T", row)
		return nil, managerError(ErrDatabase, str, nil)
	}

	// Derive and cache the managed address for the last external address.
	branch, index := ExternalBranch, acctInfo.nextExternalIndex
	if index > 0 {
		index--
	}
	lastExtAddrPath := DerivationPath{
		InternalAccount:      account,
		Account:              acctInfo.acctKeyPub.ChildIndex(),
		Branch:               branch,
		Index:                index,
		MasterKeyFingerprint: acctInfo.masterKeyFingerprint,
	}
	lastExtKey, err := s.deriveKey(acctInfo, branch, index, hasPrivateKey)
	if err != nil {
		return nil, err
	}
	lastExtAddr, err := s.keyToManaged(lastExtKey, lastExtAddrPath, acctInfo)
	if err != nil {
		return nil, err
	}
	acctInfo.lastExternalAddr = lastExtAddr

	// Derive and cache the managed address for the last internal address.
	branch, index = InternalBranch, acctInfo.nextInternalIndex
	if index > 0 {
		index--
	}
	lastIntAddrPath := DerivationPath{
		InternalAccount:      account,
		Account:              acctInfo.acctKeyPub.ChildIndex(),
		Branch:               branch,
		Index:                index,
		MasterKeyFingerprint: acctInfo.masterKeyFingerprint,
	}
	lastIntKey, err := s.deriveKey(acctInfo, branch, index, hasPrivateKey)
	if err != nil {
		return nil, err
	}
	lastIntAddr, err := s.keyToManaged(lastIntKey, lastIntAddrPath, acctInfo)
	if err != nil {
		return nil, err
	}
	acctInfo.lastInternalAddr = lastIntAddr

	// Add it to the cache and return it when everything is successful.
	s.acctInfo[account] = acctInfo
	return acctInfo, nil
}

// AccountProperties returns properties associated with the account, such as
// the account number, name, and the number of derived and imported keys.
func (s *ScopedKeyManager) AccountProperties(ns walletdb.ReadBucket,
	account uint32) (*AccountProperties, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	props := &AccountProperties{
		AccountNumber: account,
		KeyScope:      s.scope,
	}

	// Until keys can be imported into any account, special handling is
	// required for the imported account.
	//
	// loadAccountInfo errors when using it on the imported account since
	// the accountInfo struct is filled with a BIP0044 account's extended
	// keys, and the imported accounts has none.
	//
	// Since only the imported account allows imports currently, the number
	// of imported keys for any other account is zero, and since the
	// imported account cannot contain non-imported keys, the external and
	// internal key counts for it are zero.
	if account != ImportedAddrAccount {
		acctInfo, err := s.loadAccountInfo(ns, account)
		if err != nil {
			return nil, err
		}
		props.AccountName = acctInfo.acctName
		props.ExternalKeyCount = acctInfo.nextExternalIndex
		props.InternalKeyCount = acctInfo.nextInternalIndex
		props.AccountPubKey = acctInfo.acctKeyPub
		props.AccountScanKey = acctInfo.scanKey
		props.AccountSpendPubKey = acctInfo.spendPubKey
		props.MasterKeyFingerprint = acctInfo.masterKeyFingerprint
		props.IsWatchOnly = s.rootManager.watchOnly() ||
			acctInfo.acctKeyPriv == nil
		props.AddrSchema = acctInfo.addrSchema

		// Export the account public key with the correct version
		// corresponding to the manager's key scope for non-watch-only
		// accounts. This isn't done for watch-only accounts to maintain
		// the account public key consistent with what the caller
		// provided. Note that his is only done for the default key
		// scopes, as we only know the HD versions for those.
		isDefaultKeyScope := IsDefaultScope(s.scope)
		if acctInfo.acctType == accountDefault && isDefaultKeyScope {
			props.AccountPubKey, err = s.cloneKeyWithVersion(
				acctInfo.acctKeyPub,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve "+
					"account public key: %v", err)
			}
		}
	} else {
		props.AccountName = ImportedAddrAccountName // reserved, nonchangable
		props.IsWatchOnly = s.rootManager.watchOnly()

		// Could be more efficient if this was tracked by the db.
		var importedKeyCount uint32
		count := func(interface{}) error {
			importedKeyCount++
			return nil
		}
		err := forEachAccountAddress(ns, &s.scope, ImportedAddrAccount, count)
		if err != nil {
			return nil, err
		}
		props.ImportedKeyCount = importedKeyCount
	}

	return props, nil
}

// cachedKey is an entry within the LRU map that stores private keys that are
// to be used frequently. We use this wrapper struct to be able too report the
// size of a given element to the cache.
type cachedKey struct {
	key btcec.PrivateKey
}

// Size returns the size of this element. Rather than have the cache limit
// based on bytes, we simply report that each element is of size 1, meaning we
// can set our cached based on the amount of keys we want to store, rather than
// the total size of all the keys.
func (c *cachedKey) Size() (uint64, error) {
	return 1, nil
}

// DeriveFromKeyPathCache is identical to DeriveFromKeyPath, however it'll fail
// if the account refracted in the DerivationPath isn't already in the
// in-memory cache. Callers looking for faster private key retrieval can opt to
// call this method, which may fail if things aren't in the cache, then fall
// back to the normal variant. The account can information can be drawn into
// the cache if the normal DeriveFromKeyPath method is used, or the account is
// looked up via any other means.
func (s *ScopedKeyManager) DeriveFromKeyPathCache(
	kp DerivationPath) (*btcec.PrivateKey, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// First, try to look up the key itself in the proper cache, if the key
	// is here, then we don't need to do anything further.
	privKeyVal, err := s.privKeyCache.Get(kp)
	if err == nil {
		privKey := privKeyVal.key
		return &privKey, nil
	}

	// If the key isn't already in the cache, then we'll try to look up the
	// account info in the cache, if this fails, then we exit here as we
	// can't move forward without creating a DB transaction, and the point
	// of this method is to avoid that.
	acctInfo, ok := s.acctInfo[kp.InternalAccount]
	if !ok {
		return nil, managerError(
			ErrAccountNotCached,
			"", fmt.Errorf("acct %v not cached", kp.InternalAccount),
		)
	}

	watchOnly := s.rootManager.watchOnly()
	private := !s.rootManager.isLocked() && !watchOnly

	// Now that we have the account information, we can derive the key
	// directly.
	addrKey, err := s.deriveKey(acctInfo, kp.Branch, kp.Index, private)
	if err != nil {
		return nil, err
	}

	// Now that we have the key, we'll attempt to insert it into the cache,
	// and return it as is.
	privKey, err := addrKey.ECPrivKey()
	if err != nil {
		return nil, err
	}
	_, err = s.privKeyCache.Put(kp, &cachedKey{key: *privKey})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// DeriveFromKeyPath attempts to derive a maximal child key (under the BIP0044
// scheme) from a given key path. If key derivation isn't possible, then an
// error will be returned.
//
// NOTE: The key will be derived from the account stored in the database under
// the InternalAccount number.
func (s *ScopedKeyManager) DeriveFromKeyPath(ns walletdb.ReadBucket,
	kp DerivationPath) (ManagedAddress, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	watchOnly := s.rootManager.watchOnly()
	private := !s.rootManager.isLocked() && !watchOnly

	addrKey, _, _, err := s.deriveKeyFromPath(
		ns, kp.InternalAccount, kp.Branch, kp.Index, private,
	)
	if err != nil {
		return nil, err
	}

	acctInfo, err := s.loadAccountInfo(ns, kp.InternalAccount)
	if err != nil {
		return nil, err
	}
	return s.keyToManaged(addrKey, kp, acctInfo)
}

// deriveKeyFromPath returns either a public or private derived extended key
// based on the private flag for an address given an account, branch, and index.
// The account master key is also returned.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) deriveKeyFromPath(ns walletdb.ReadBucket,
	internalAccount, branch, index uint32, private bool) (
	*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, uint32, error) {

	// Look up the account key information.
	acctInfo, err := s.loadAccountInfo(ns, internalAccount)
	if err != nil {
		return nil, nil, 0, err
	}
	private = private && acctInfo.acctKeyPriv != nil

	addrKey, err := s.deriveKey(acctInfo, branch, index, private)
	if err != nil {
		return nil, nil, 0, err
	}

	acctKey := acctInfo.acctKeyPub
	if private {
		acctKey = acctInfo.acctKeyPriv
	}

	return addrKey, acctKey, acctInfo.masterKeyFingerprint, nil
}

// chainAddressRowToManaged returns a new managed address based on chained
// address data loaded from the database.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) chainAddressRowToManaged(ns walletdb.ReadBucket,
	row *dbChainAddressRow) (ManagedAddress, error) {

	// Since the manger's mutex is assumed to held when invoking this
	// function, we use the internal isLocked to avoid a deadlock.
	private := !s.rootManager.isLocked() && !s.rootManager.watchOnly()

	addressKey, acctKey, masterKeyFingerprint, err := s.deriveKeyFromPath(
		ns, row.account, row.branch, row.index, private,
	)
	if err != nil {
		return nil, err
	}

	acctInfo, err := s.loadAccountInfo(ns, row.account)
	if err != nil {
		return nil, err
	}
	return s.keyToManaged(
		addressKey, DerivationPath{
			InternalAccount:      row.account,
			Account:              acctKey.ChildIndex(),
			Branch:               row.branch,
			Index:                row.index,
			MasterKeyFingerprint: masterKeyFingerprint,
		}, acctInfo,
	)
}

// importedAddressRowToManaged returns a new managed address based on imported
// address data loaded from the database.
func (s *ScopedKeyManager) importedAddressRowToManaged(row *dbImportedAddressRow) (ManagedAddress, error) {

	// Use the crypto public key to decrypt the imported public key.
	pubBytes, err := s.rootManager.cryptoKeyPub.Decrypt(row.encryptedPubKey)
	if err != nil {
		str := "failed to decrypt public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	pubKey, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		str := "invalid public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	// TODO: Handle imported key being part of internal branch.
	compressed := len(pubBytes) == btcec.PubKeyBytesLenCompressed
	ma, err := newManagedAddressWithoutPrivKey(
		s, ImportedDerivationPath, pubKey, nil, compressed,
		s.addrSchema.ExternalAddrType,
	)
	if err != nil {
		return nil, err
	}
	ma.privKeyEncrypted = row.encryptedPrivKey
	ma.imported = true

	return ma, nil
}

// scriptAddressRowToManaged returns a new managed address based on script
// address data loaded from the database.
func (s *ScopedKeyManager) scriptAddressRowToManaged(
	row *dbScriptAddressRow) (ManagedAddress, error) {

	// Use the crypto public key to decrypt the imported script hash.
	scriptHash, err := s.rootManager.cryptoKeyPub.Decrypt(row.encryptedHash)
	if err != nil {
		str := "failed to decrypt imported script hash"
		return nil, managerError(ErrCrypto, str, err)
	}

	return newScriptAddress(s, row.account, scriptHash, row.encryptedScript)
}

// witnessScriptAddressRowToManaged returns a new managed address based on
// witness script address data loaded from the database.
func (s *ScopedKeyManager) witnessScriptAddressRowToManaged(
	row *dbWitnessScriptAddressRow) (ManagedAddress, error) {

	// Use the crypto public key to decrypt the imported script hash.
	scriptHash, err := s.rootManager.cryptoKeyPub.Decrypt(row.encryptedHash)
	if err != nil {
		str := "failed to decrypt imported witness script hash"
		return nil, managerError(ErrCrypto, str, err)
	}

	return newWitnessScriptAddress(
		s, row.account, scriptHash, row.encryptedScript,
		row.witnessVersion, row.isSecretScript,
	)
}

// rowInterfaceToManaged returns a new managed address based on the given
// address data loaded from the database.  It will automatically select the
// appropriate type.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) rowInterfaceToManaged(ns walletdb.ReadBucket,
	rowInterface interface{}) (ManagedAddress, error) {

	switch row := rowInterface.(type) {
	case *dbChainAddressRow:
		return s.chainAddressRowToManaged(ns, row)

	case *dbImportedAddressRow:
		return s.importedAddressRowToManaged(row)

	case *dbScriptAddressRow:
		return s.scriptAddressRowToManaged(row)

	case *dbWitnessScriptAddressRow:
		return s.witnessScriptAddressRowToManaged(row)
	}

	str := fmt.Sprintf("unsupported address type %T", rowInterface)
	return nil, managerError(ErrDatabase, str, nil)
}

// loadAndCacheAddress attempts to load the passed address from the database
// and caches the associated managed address.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) loadAndCacheAddress(ns walletdb.ReadBucket,
	address ltcutil.Address) (ManagedAddress, error) {

	// Attempt to load the raw address information from the database.
	rowInterface, err := fetchAddress(ns, &s.scope, address.ScriptAddress())
	if err != nil {
		if merr, ok := err.(*ManagerError); ok {
			desc := fmt.Sprintf("failed to fetch address '%s': %v",
				address.ScriptAddress(), merr.Description)
			merr.Description = desc
			return nil, merr
		}
		return nil, maybeConvertDbError(err)
	}

	// Create a new managed address for the specific type of address based
	// on type.
	managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
	if err != nil {
		return nil, err
	}

	// Cache and return the new managed address.
	s.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr

	return managedAddr, nil
}

// existsAddress returns whether or not the passed address is known to the
// address manager.
//
// This function MUST be called with the manager lock held for reads.
func (s *ScopedKeyManager) existsAddress(ns walletdb.ReadBucket, addressID []byte) bool {
	// Check the in-memory map first since it's faster than a db access.
	if _, ok := s.addrs[addrKey(addressID)]; ok {
		return true
	}

	// Check the database if not already found above.
	return existsAddress(ns, &s.scope, addressID)
}

// Address returns a managed address given the passed address if it is known to
// the address manager.  A managed address differs from the passed address in
// that it also potentially contains extra information needed to sign
// transactions such as the associated private key for pay-to-pubkey and
// pay-to-pubkey-hash addresses and the script associated with
// pay-to-script-hash addresses.
func (s *ScopedKeyManager) Address(ns walletdb.ReadBucket,
	address ltcutil.Address) (ManagedAddress, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	return s.address(ns, address)
}

func (s *ScopedKeyManager) address(ns walletdb.ReadBucket,
	address ltcutil.Address) (ManagedAddress, error) {

	// ScriptAddress will only return a script hash if we're accessing an
	// address that is either PKH or SH. In the event we're passed a PK
	// address, convert the PK to PKH address so that we can access it from
	// the addrs map and database.
	if pka, ok := address.(*ltcutil.AddressPubKey); ok {
		address = pka.AddressPubKeyHash()
	}

	// Return the address from cache if it's available.
	//
	// NOTE: Not using a defer on the lock here since a write lock is
	// needed if the lookup fails.
	s.mtx.RLock()
	if ma, ok := s.addrs[addrKey(address.ScriptAddress())]; ok {
		s.mtx.RUnlock()
		return ma, nil
	}
	s.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Attempt to load the address from the database.
	return s.loadAndCacheAddress(ns, address)
}

// AddrAccount returns the account to which the given address belongs.
func (s *ScopedKeyManager) AddrAccount(ns walletdb.ReadBucket,
	address ltcutil.Address) (uint32, error) {

	account, err := fetchAddrAccount(ns, &s.scope, address.ScriptAddress())
	if err != nil {
		return 0, maybeConvertDbError(err)
	}

	return account, nil
}

// accountAddrType determines the type of address that should be generated for
// an account based on whether it's an internal address or not.
func (s *ScopedKeyManager) accountAddrType(acctInfo *accountInfo,
	internal bool) AddressType {

	// If the account has a custom address schema, use it.
	addrSchema := s.addrSchema
	if acctInfo.addrSchema != nil {
		addrSchema = *acctInfo.addrSchema
	}

	if internal {
		return addrSchema.InternalAddrType
	}
	return addrSchema.ExternalAddrType
}

// nextAddresses returns the specified number of next chained address from the
// branch indicated by the internal flag.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) nextAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32, internal bool) ([]ManagedAddress, error) {

	// The next address can only be generated for accounts that have
	// already been created.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	// Choose the account key to used based on whether the address manager
	// is locked.
	acctKey := acctInfo.acctKeyPub
	watchOnly := s.rootManager.watchOnly() || len(acctInfo.acctKeyEncrypted) == 0
	if !s.rootManager.isLocked() && !watchOnly {
		acctKey = acctInfo.acctKeyPriv
	}

	// Choose the branch key and index depending on whether or not this is
	// an internal address.
	branchNum, nextIndex := ExternalBranch, acctInfo.nextExternalIndex
	if internal {
		branchNum = InternalBranch
		nextIndex = acctInfo.nextInternalIndex
	}

	// Choose the appropriate type of address to derive since it's possible
	// for a watch-only account to have a different schema from the
	// manager's.
	addrType := s.accountAddrType(acctInfo, internal)

	// Ensure the requested number of addresses doesn't exceed the maximum
	// allowed for this account.
	if numAddresses > MaxAddressesPerAccount || nextIndex+numAddresses >
		MaxAddressesPerAccount {
		str := fmt.Sprintf("%d new addresses would exceed the maximum "+
			"allowed number of addresses per account of %d",
			numAddresses, MaxAddressesPerAccount)
		return nil, managerError(ErrTooManyAddresses, str, nil)
	}

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.DeriveNonStandard(branchNum) // nolint:staticcheck
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branchNum)
		return nil, managerError(ErrKeyChain, str, err)
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	// Create the requested number of addresses and keep track of the index
	// with each one.
	addressInfo := make([]*unlockDeriveInfo, 0, numAddresses)
	for i := uint32(0); i < numAddresses; i++ {
		// There is an extremely small chance that a particular child is
		// invalid, so use a loop to derive the next valid child.
		var nextKey *hdkeychain.ExtendedKey
		for {
			if acctInfo.scanKey != nil {
				nextKey, err = s.deriveSpendKey(acctKey, acctInfo, nextIndex)
				if err != nil {
					return nil, err
				}
				nextIndex++
				break
			}

			// Derive the next child in the external chain branch.
			key, err := branchKey.DeriveNonStandard(nextIndex) // nolint:staticcheck
			if err != nil {
				// When this particular child is invalid, skip to the
				// next index.
				if err == hdkeychain.ErrInvalidChild {
					nextIndex++
					continue
				}

				str := fmt.Sprintf("failed to generate child %d",
					nextIndex)
				return nil, managerError(ErrKeyChain, str, err)
			}
			key.SetNet(s.rootManager.chainParams)

			nextIndex++
			nextKey = key
			break
		}

		// Now that we know this key can be used, we'll create the
		// proper derivation path so this information can be available
		// to callers.
		derivationPath := DerivationPath{
			InternalAccount: account,
			Account:         acctKey.ChildIndex(),
			Branch:          branchNum,
			Index:           nextIndex - 1,
		}

		// Create a new managed address based on the public or private
		// key depending on whether the generated key is private.
		// Also, zero the next key after creating the managed address
		// from it.
		addr, err := newManagedAddressFromExtKey(
			s, derivationPath, nextKey, addrType, acctInfo,
		)
		if err != nil {
			return nil, err
		}
		if internal {
			addr.internal = true
		}
		managedAddr := addr
		nextKey.Zero()

		info := unlockDeriveInfo{
			managedAddr: managedAddr,
			branch:      branchNum,
			index:       nextIndex - 1,
		}
		addressInfo = append(addressInfo, &info)
	}

	// Now that all addresses have been successfully generated, update the
	// database in a single transaction.
	for _, info := range addressInfo {
		ma := info.managedAddr
		addressID := ma.Address().ScriptAddress()

		switch a := ma.(type) {
		case *managedAddress:
			err := putChainedAddress(
				ns, &s.scope, addressID, account, ssFull,
				info.branch, info.index, adtChain,
			)
			if err != nil {
				return nil, maybeConvertDbError(err)
			}

		case *scriptAddress:
			encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(
				a.AddrHash(),
			)
			if err != nil {
				str := fmt.Sprintf("failed to encrypt script hash %x",
					a.AddrHash())
				return nil, managerError(ErrCrypto, str, err)
			}

			err = putScriptAddress(
				ns, &s.scope, a.AddrHash(), ImportedAddrAccount,
				ssNone, encryptedHash, a.scriptEncrypted,
			)
			if err != nil {
				return nil, maybeConvertDbError(err)
			}

		}

		// Now that we've written the address, we'll read it back from
		// disk to ensure that it's the same address we have in memory.
		diskAddr, err := s.loadAndCacheAddress(ns, ma.Address())
		if err != nil {
			return nil, maybeConvertDbError(err)
		}

		if ma.Address().String() != diskAddr.Address().String() {
			// The address didn't match up, so we'll manually
			// delete it from the cache.
			delete(
				s.addrs,
				addrKey(diskAddr.Address().ScriptAddress()),
			)

			return nil, fmt.Errorf("%w (disk read): "+
				"expected %v, got %v", ErrAddrMismatch,
				diskAddr.Address().String(),
				ma.Address().String())
		}
	}

	managedAddresses := make([]ManagedAddress, 0, len(addressInfo))
	for _, info := range addressInfo {
		ma := info.managedAddr
		managedAddresses = append(managedAddresses, ma)
	}

	// Finally, create a closure that will update the next address tracking
	// and add the addresses to the cache after the newly generated
	// addresses have been successfully committed to the db.
	onCommit := func() {
		// Since this closure will be called when the DB transaction
		// gets committed, we won't longer be holding the manager's
		// mutex at that point. We must therefore re-acquire it before
		// continuing.
		s.rootManager.mtx.RLock()
		defer s.rootManager.mtx.RUnlock()

		s.mtx.Lock()
		defer s.mtx.Unlock()

		for _, info := range addressInfo {
			ma := info.managedAddr
			s.addrs[addrKey(ma.Address().ScriptAddress())] = ma

			// Add the new managed address to the list of addresses
			// that need their private keys derived when the
			// address manager is next unlocked.
			if s.rootManager.isLocked() && !watchOnly {
				s.deriveOnUnlock = append(s.deriveOnUnlock, info)
			}
		}

		// Set the last address and next address for tracking.
		ma := addressInfo[len(addressInfo)-1].managedAddr
		if internal {
			acctInfo.nextInternalIndex = nextIndex
			acctInfo.lastInternalAddr = ma
		} else {
			acctInfo.nextExternalIndex = nextIndex
			acctInfo.lastExternalAddr = ma
		}
	}
	ns.Tx().OnCommit(onCommit)

	return managedAddresses, nil
}

// extendAddresses ensures that all addresses up to and including the lastIndex
// are derived for either an internal or external branch. If the child at
// lastIndex is invalid, this method will proceed until the next valid child is
// found. An error is returned if method failed to properly extend addresses
// up to the requested index.
//
// This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) extendAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32, internal bool) error {

	// The next address can only be generated for accounts that have
	// already been created.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return err
	}

	// Choose the account key to used based on whether the address manager
	// is locked.
	acctKey := acctInfo.acctKeyPub
	watchOnly := s.rootManager.watchOnly() || acctInfo.acctKeyPriv != nil
	if !s.rootManager.isLocked() && !watchOnly {
		acctKey = acctInfo.acctKeyPriv
	}

	// Choose the branch key and index depending on whether or not this is
	// an internal address.
	branchNum, nextIndex := ExternalBranch, acctInfo.nextExternalIndex
	if internal {
		branchNum = InternalBranch
		nextIndex = acctInfo.nextInternalIndex
	}

	// Choose the appropriate type of address to derive since it's possible
	// for a watch-only account to have a different schema from the
	// manager's.
	addrType := s.accountAddrType(acctInfo, internal)

	// If the last index requested is already lower than the next index, we
	// can return early.
	if lastIndex < nextIndex {
		return nil
	}

	// Ensure the requested number of addresses doesn't exceed the maximum
	// allowed for this account.
	if lastIndex > MaxAddressesPerAccount {
		str := fmt.Sprintf("last index %d would exceed the maximum "+
			"allowed number of addresses per account of %d",
			lastIndex, MaxAddressesPerAccount)
		return managerError(ErrTooManyAddresses, str, nil)
	}

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.DeriveNonStandard(branchNum) // nolint:staticcheck
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branchNum)
		return managerError(ErrKeyChain, str, err)
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	// Starting from this branch's nextIndex, derive all child indexes up to
	// and including the requested lastIndex. If a invalid child is
	// detected, this loop will continue deriving until it finds the next
	// subsequent index.
	addressInfo := make([]*unlockDeriveInfo, 0, lastIndex-nextIndex)
	for nextIndex <= lastIndex {
		// There is an extremely small chance that a particular child is
		// invalid, so use a loop to derive the next valid child.
		var nextKey *hdkeychain.ExtendedKey
		for {
			if acctInfo.scanKey != nil {
				nextKey, err = s.deriveSpendKey(acctKey, acctInfo, nextIndex)
				if err != nil {
					return err
				}
				nextIndex++
				break
			}

			// Derive the next child in the external chain branch.
			key, err := branchKey.DeriveNonStandard(nextIndex) // nolint:staticcheck
			if err != nil {
				// When this particular child is invalid, skip to the
				// next index.
				if err == hdkeychain.ErrInvalidChild {
					nextIndex++
					continue
				}

				str := fmt.Sprintf("failed to generate child %d",
					nextIndex)
				return managerError(ErrKeyChain, str, err)
			}
			key.SetNet(s.rootManager.chainParams)

			nextIndex++
			nextKey = key
			break
		}

		// Now that we know this key can be used, we'll create the
		// proper derivation path so this information can be available
		// to callers.
		derivationPath := DerivationPath{
			InternalAccount: account,
			Account:         acctInfo.acctKeyPub.ChildIndex(),
			Branch:          branchNum,
			Index:           nextIndex - 1,
		}

		// Create a new managed address based on the public or private
		// key depending on whether the generated key is private.
		// Also, zero the next key after creating the managed address
		// from it.
		addr, err := newManagedAddressFromExtKey(
			s, derivationPath, nextKey, addrType, acctInfo,
		)
		if err != nil {
			return err
		}
		if internal {
			addr.internal = true
		}
		managedAddr := addr
		nextKey.Zero()

		info := unlockDeriveInfo{
			managedAddr: managedAddr,
			branch:      branchNum,
			index:       nextIndex - 1,
		}
		addressInfo = append(addressInfo, &info)
	}

	// Now that all addresses have been successfully generated, update the
	// database in a single transaction.
	for _, info := range addressInfo {
		ma := info.managedAddr
		addressID := ma.Address().ScriptAddress()

		switch a := ma.(type) {
		case *managedAddress:
			err := putChainedAddress(
				ns, &s.scope, addressID, account, ssFull,
				info.branch, info.index, adtChain,
			)
			if err != nil {
				return maybeConvertDbError(err)
			}
		case *scriptAddress:
			encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(a.AddrHash())
			if err != nil {
				str := fmt.Sprintf("failed to encrypt script hash %x",
					a.AddrHash())
				return managerError(ErrCrypto, str, err)
			}

			err = putScriptAddress(
				ns, &s.scope, a.AddrHash(), ImportedAddrAccount,
				ssNone, encryptedHash, a.scriptEncrypted,
			)
			if err != nil {
				return maybeConvertDbError(err)
			}
		}
	}

	// Finally update the next address tracking and add the addresses to
	// the cache after the newly generated addresses have been successfully
	// added to the db.
	for _, info := range addressInfo {
		ma := info.managedAddr
		s.addrs[addrKey(ma.Address().ScriptAddress())] = ma

		// Add the new managed address to the list of addresses that
		// need their private keys derived when the address manager is
		// next unlocked.
		if s.rootManager.isLocked() && !watchOnly {
			s.deriveOnUnlock = append(s.deriveOnUnlock, info)
		}
	}

	// Set the last address and next address for tracking.
	ma := addressInfo[len(addressInfo)-1].managedAddr
	if internal {
		acctInfo.nextInternalIndex = nextIndex
		acctInfo.lastInternalAddr = ma
	} else {
		acctInfo.nextExternalIndex = nextIndex
		acctInfo.lastExternalAddr = ma
	}

	return nil
}

// NextExternalAddresses returns the specified number of next chained addresses
// that are intended for external use from the address manager.
func (s *ScopedKeyManager) NextExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32) ([]ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.nextAddresses(ns, account, numAddresses, false)
}

// NextInternalAddresses returns the specified number of next chained addresses
// that are intended for internal use such as change from the address manager.
func (s *ScopedKeyManager) NextInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, numAddresses uint32) ([]ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.nextAddresses(ns, account, numAddresses, true)
}

// ExtendExternalAddresses ensures that all valid external keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to a external child that was found
// during recovery.
func (s *ScopedKeyManager) ExtendExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32) error {

	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.extendAddresses(ns, account, lastIndex, false)
}

// ExtendInternalAddresses ensures that all valid internal keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to an internal child that was found
// during recovery.
func (s *ScopedKeyManager) ExtendInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32) error {

	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.extendAddresses(ns, account, lastIndex, true)
}

// LastExternalAddress returns the most recently requested chained external
// address from calling NextExternalAddress for the given account.  The first
// external address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (s *ScopedKeyManager) LastExternalAddress(ns walletdb.ReadBucket,
	account uint32) (ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextExternalIndex > 0 {
		return acctInfo.lastExternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous external address", nil)
}

// LastInternalAddress returns the most recently requested chained internal
// address from calling NextInternalAddress for the given account.  The first
// internal address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (s *ScopedKeyManager) LastInternalAddress(ns walletdb.ReadBucket,
	account uint32) (ManagedAddress, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextInternalIndex > 0 {
		return acctInfo.lastInternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous internal address", nil)
}

// NewRawAccount creates a new account for the scoped manager. This method
// differs from the NewAccount method in that this method takes the account
// number *directly*, rather than taking a string name for the account, then
// mapping that to the next highest account number.
func (s *ScopedKeyManager) NewRawAccount(ns walletdb.ReadWriteBucket, number uint32) error {
	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	if s.rootManager.watchOnly() {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	if s.rootManager.isLocked() {
		return managerError(ErrLocked, errLocked, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// As this is an ad hoc account that may not follow our normal linear
	// derivation, we'll create a new name for this account based off of
	// the account number.
	name := fmt.Sprintf("act:%v", number)
	return s.newAccount(ns, number, name)
}

// NewRawAccountWatchingOnly creates a new watching only account for the scoped
// manager. This method differs from the NewAccountWatchingOnly method in that
// this method takes the account number *directly*, rather than taking a string
// name for the account, then mapping that to the next highest account number.
//
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
//
// An optional address schema may also be provided to override the
// ScopedKeyManager's address schema. This will affect all addresses derived
// from the account.
func (s *ScopedKeyManager) NewRawAccountWatchingOnly(
	ns walletdb.ReadWriteBucket, number uint32,
	pubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrSchema *ScopeAddrSchema) error {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// As this is an ad hoc account that may not follow our normal linear
	// derivation, we'll create a new name for this account based off of
	// the account number.
	name := fmt.Sprintf("act:%v", number)
	return s.newAccountWatchingOnly(
		ns, number, name, pubKey, masterKeyFingerprint, addrSchema,
	)
}

// NewAccount creates and returns a new account stored in the manager based on
// the given account name.  If an account with the same name already exists,
// ErrDuplicateAccount will be returned.  Since creating a new account requires
// access to the cointype keys (from which extended account keys are derived),
// it requires the manager to be unlocked.
func (s *ScopedKeyManager) NewAccount(ns walletdb.ReadWriteBucket, name string) (uint32, error) {
	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	if s.rootManager.watchOnly() {
		return 0, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	if s.rootManager.isLocked() {
		return 0, managerError(ErrLocked, errLocked, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Fetch latest account, and create a new account in the same
	// transaction Fetch the latest account number to generate the next
	// account number
	account, err := fetchLastAccount(ns, &s.scope)
	if err != nil {
		return 0, err
	}
	account++

	// With the name validated, we'll create a new account for the new
	// contiguous account.
	if err := s.newAccount(ns, account, name); err != nil {
		return 0, err
	}

	return account, nil
}

// newAccount is a helper function that derives a new precise account number,
// and creates a mapping from the passed name to the account number in the
// database.
//
// NOTE: This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) newAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	// Validate the account name.
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	// Check that account with the same name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := "account with the same name already exists"
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Fetch the cointype key which will be used to derive the next account
	// extended keys
	_, coinTypePrivEnc, err := fetchCoinTypeKeys(ns, &s.scope)
	if err != nil {
		return err
	}

	// Decrypt the cointype key.
	serializedKeyPriv, err := s.rootManager.cryptoKeyPriv.Decrypt(coinTypePrivEnc)
	if err != nil {
		str := "failed to decrypt cointype serialized private key"
		return managerError(ErrLocked, str, err)
	}
	coinTypeKeyPriv, err := hdkeychain.NewKeyFromString(string(serializedKeyPriv))
	zero.Bytes(serializedKeyPriv)
	if err != nil {
		str := "failed to create cointype extended private key"
		return managerError(ErrKeyChain, str, err)
	}

	// Derive the account key using the cointype key
	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, account)
	coinTypeKeyPriv.Zero()
	if err != nil {
		str := "failed to convert private key for account"
		return managerError(ErrKeyChain, str, err)
	}
	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		str := "failed to convert public key for account"
		return managerError(ErrKeyChain, str, err)
	}

	acctKeyScan, err := acctKeyPriv.Derive(hdkeychain.HardenedKeyStart)
	if err != nil {
		str := "failed to derive scan key"
		return managerError(ErrKeyChain, str, err)
	}
	defer acctKeyScan.Zero() // Ensure key is zeroed when done.

	spendKey, err := acctKeyPriv.Derive(hdkeychain.HardenedKeyStart + 1)
	if err != nil {
		str := "failed to derive spend key"
		return managerError(ErrKeyChain, str, err)
	}
	defer spendKey.Zero() // Ensure key is zeroed when done.
	acctKeySpend, _ := spendKey.Neuter()

	// Encrypt the default account keys with the associated crypto keys.
	acctPubEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(acctKeyPub.String()),
	)
	if err != nil {
		str := "failed to encrypt public key for account"
		return managerError(ErrCrypto, str, err)
	}
	acctPrivEnc, err := s.rootManager.cryptoKeyPriv.Encrypt(
		[]byte(acctKeyPriv.String()),
	)
	if err != nil {
		str := "failed to encrypt private key for account"
		return managerError(ErrCrypto, str, err)
	}
	acctScanEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(acctKeyScan.String()),
	)
	if err != nil {
		str := "failed to encrypt scan key for account"
		return managerError(ErrCrypto, str, err)
	}
	acctSpendEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(acctKeySpend.String()),
	)
	if err != nil {
		str := "failed to encrypt spend key for account"
		return managerError(ErrCrypto, str, err)
	}
	if s.scope != KeyScopeMweb {
		acctScanEnc = nil
		acctSpendEnc = nil
	}

	// We have the encrypted account extended keys, so save them to the
	// database
	err = putDefaultAccountInfo(
		ns, &s.scope, account, acctPubEnc, acctPrivEnc,
		acctScanEnc, acctSpendEnc, 0, 0, name,
	)
	if err != nil {
		return err
	}

	// Save last account metadata
	return putLastAccount(ns, &s.scope, account)
}

// NewAccountWatchingOnly is similar to NewAccount, but for watch-only wallets.
//
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
//
// An optional address schema may also be provided to override the
// ScopedKeyManager's address schema. This will affect all addresses derived
// from the account.
func (s *ScopedKeyManager) NewAccountWatchingOnly(ns walletdb.ReadWriteBucket,
	name string, pubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrSchema *ScopeAddrSchema) (uint32, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Fetch latest account, and create a new account in the same
	// transaction Fetch the latest account number to generate the next
	// account number
	account, err := fetchLastAccount(ns, &s.scope)
	if err != nil {
		return 0, err
	}
	account++

	// With the name validated, we'll create a new account for the new
	// contiguous account.
	err = s.newAccountWatchingOnly(
		ns, account, name, pubKey, masterKeyFingerprint, addrSchema,
	)
	if err != nil {
		return 0, err
	}

	return account, nil
}

// newAccountWatchingOnly is similar to newAccount, but for watching-only wallets.
//
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
//
// An optional address schema may also be provided to override the
// ScopedKeyManager's address schema. This will affect all addresses derived
// from the account.
//
// NOTE: This function MUST be called with the manager lock held for writes.
func (s *ScopedKeyManager) newAccountWatchingOnly(ns walletdb.ReadWriteBucket,
	account uint32, name string, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrSchema *ScopeAddrSchema) error {

	// Validate the account name.
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	// Check that account with the same name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := "account with the same name already exists"
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Encrypt the default account keys with the associated crypto keys.
	acctPubEnc, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(pubKey.String()),
	)
	if err != nil {
		str := "failed to encrypt public key for account"
		return managerError(ErrCrypto, str, err)
	}

	// We have the encrypted account extended keys, so save them to the
	// database
	err = putWatchOnlyAccountInfo(
		ns, &s.scope, account, acctPubEnc, masterKeyFingerprint, 0, 0,
		name, addrSchema,
	)
	if err != nil {
		return err
	}

	// Save last account metadata
	return putLastAccount(ns, &s.scope, account)
}

// RenameAccount renames an account stored in the manager based on the given
// account number with the given name.  If an account with the same name
// already exists, ErrDuplicateAccount will be returned.
func (s *ScopedKeyManager) RenameAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Ensure that a reserved account is not being renamed.
	if isReservedAccountNum(account) {
		str := "reserved account cannot be renamed"
		return managerError(ErrInvalidAccount, str, nil)
	}

	// Check that account with the new name does not exist
	_, err := s.lookupAccount(ns, name)
	if err == nil {
		str := "account with the same name already exists"
		return managerError(ErrDuplicateAccount, str, err)
	}

	// Validate account name
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	rowInterface, err := fetchAccountInfo(ns, &s.scope, account)
	if err != nil {
		return err
	}

	// Remove the old name key from the account id index.
	if err = deleteAccountIDIndex(ns, &s.scope, account); err != nil {
		return err
	}

	switch row := rowInterface.(type) {
	case *dbDefaultAccountRow:
		// Remove the old name key from the account name index.
		if err = deleteAccountNameIndex(ns, &s.scope, row.name); err != nil {
			return err
		}

		err = putDefaultAccountInfo(
			ns, &s.scope, account, row.pubKeyEncrypted, row.privKeyEncrypted,
			row.scanKeyEncrypted, row.spendPubKeyEncrypted,
			row.nextExternalIndex, row.nextInternalIndex, name,
		)
		if err != nil {
			return err
		}

	case *dbWatchOnlyAccountRow:
		// Remove the old name key from the account name index.
		if err = deleteAccountNameIndex(ns, &s.scope, row.name); err != nil {
			return err
		}

		err = putWatchOnlyAccountInfo(
			ns, &s.scope, account, row.pubKeyEncrypted,
			row.masterKeyFingerprint, row.nextExternalIndex,
			row.nextInternalIndex, name, row.addrSchema,
		)
		if err != nil {
			return err
		}

	default:
		str := fmt.Sprintf("unsupported account type %T", row)
		return managerError(ErrDatabase, str, nil)
	}

	// Update in-memory account info with new name if cached and the db
	// write was successful.
	if err == nil {
		if acctInfo, ok := s.acctInfo[account]; ok {
			acctInfo.acctName = name
		}
	}

	return err
}

// ImportPrivateKey imports a WIF private key into the address manager.  The
// imported address is created using either a compressed or uncompressed
// serialized public key, depending on the CompressPubKey bool of the WIF.
//
// All imported addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// NOTE: When the address manager is watching-only, the private key itself will
// not be stored or available since it is private data.  Instead, only the
// public key will be stored.  This means it is paramount the private key is
// kept elsewhere as the watching-only address manager will NOT ever have access
// to it.
//
// This function will return an error if the address manager is locked and not
// watching-only, or not for the same network as the key trying to be imported.
// It will also return an error if the address already exists.  Any other
// errors returned are generally unexpected.
func (s *ScopedKeyManager) ImportPrivateKey(ns walletdb.ReadWriteBucket,
	wif *ltcutil.WIF, bs *BlockStamp) (ManagedPubKeyAddress, error) {

	// Ensure the address is intended for network the address manager is
	// associated with.
	if !wif.IsForNet(s.rootManager.chainParams) {
		str := fmt.Sprintf("private key is not for the same network the "+
			"address manager is configured for (%s)",
			s.rootManager.chainParams.Name)
		return nil, managerError(ErrWrongNet, str, nil)
	}

	s.rootManager.mtx.Lock()
	defer s.rootManager.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported private key.
	if s.rootManager.isLocked() && !s.rootManager.watchOnly() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Encrypt the private key when not a watching-only address manager.
	var encryptedPrivKey []byte
	if !s.rootManager.watchOnly() {
		privKeyBytes := wif.PrivKey.Serialize()
		var err error
		encryptedPrivKey, err = s.rootManager.cryptoKeyPriv.Encrypt(privKeyBytes)
		zero.Bytes(privKeyBytes)
		if err != nil {
			str := fmt.Sprintf("failed to encrypt private key for %x",
				wif.PrivKey.PubKey().SerializeCompressed())
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	err := s.importPublicKey(
		ns, wif.SerializePubKey(), encryptedPrivKey,
		s.addrSchema.ExternalAddrType, bs,
	)
	if err != nil {
		return nil, err
	}

	// Create a new managed address based on the imported address.
	if !s.rootManager.watchOnly() {
		return s.toImportedPrivateManagedAddress(wif)
	}
	pubKey := wif.PrivKey.PubKey()
	return s.toImportedPublicManagedAddress(pubKey, wif.CompressPubKey)
}

// ImportPublicKey imports a public key into the address manager.
//
// All imported addresses will be part of the account defined by the
// ImportedAddrAccount constant.
func (s *ScopedKeyManager) ImportPublicKey(ns walletdb.ReadWriteBucket,
	pubKey *btcec.PublicKey, bs *BlockStamp) (ManagedAddress, error) {

	s.rootManager.mtx.Lock()
	defer s.rootManager.mtx.Unlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	serializedPubKey := pubKey.SerializeCompressed()
	err := s.importPublicKey(
		ns, serializedPubKey, nil, s.addrSchema.ExternalAddrType, bs,
	)
	if err != nil {
		return nil, err
	}

	return s.toImportedPublicManagedAddress(pubKey, true)
}

// importPublicKey imports a public key into the address manager and updates the
// wallet's start block if necessary. An error is returned if the public key
// already exists.
func (s *ScopedKeyManager) importPublicKey(ns walletdb.ReadWriteBucket,
	serializedPubKey, encryptedPrivKey []byte, addrType AddressType,
	bs *BlockStamp) error {

	// Compute the addressID for our key based on its address type.
	var addressID []byte
	switch addrType {
	case PubKeyHash, WitnessPubKey:
		addressID = ltcutil.Hash160(serializedPubKey)

	case NestedWitnessPubKey:
		pubKeyHash := ltcutil.Hash160(serializedPubKey)
		p2wkhAddr, err := ltcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, s.rootManager.chainParams,
		)
		if err != nil {
			return err
		}
		witnessScript, err := txscript.PayToAddrScript(p2wkhAddr)
		if err != nil {
			return err
		}
		addressID = ltcutil.Hash160(witnessScript)

	case TaprootPubKey:
		internalPubKey, err := btcec.ParsePubKey(serializedPubKey)
		if err != nil {
			return err
		}
		taprootPubKey := txscript.ComputeTaprootKeyNoScript(
			internalPubKey,
		)
		addressID = schnorr.SerializePubKey(taprootPubKey)

	default:
		return fmt.Errorf("unsupported address type %v", addrType)
	}

	// Prevent duplicates.
	alreadyExists := s.existsAddress(ns, addressID)
	if alreadyExists {
		str := fmt.Sprintf("address for public key %x already exists",
			serializedPubKey)
		return managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt public key.
	encryptedPubKey, err := s.rootManager.cryptoKeyPub.Encrypt(
		serializedPubKey,
	)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt public key for %x",
			serializedPubKey)
		return managerError(ErrCrypto, str, err)
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	updateStartBlock := bs != nil &&
		bs.Height < s.rootManager.syncState.startBlock.Height

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	err = putImportedAddress(
		ns, &s.scope, addressID, ImportedAddrAccount, ssNone,
		encryptedPubKey, encryptedPrivKey,
	)
	if err != nil {
		return err
	}

	if updateStartBlock {
		err := putStartBlock(ns, bs)
		if err != nil {
			return err
		}
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		s.rootManager.syncState.startBlock = *bs
	}

	return nil
}

// toImportedPrivateManagedAddress converts an imported private key to an
// imported managed address.
func (s *ScopedKeyManager) toImportedPrivateManagedAddress(
	wif *ltcutil.WIF) (*managedAddress, error) {

	// Create a new managed address based on the imported address.
	//
	// TODO: Handle imported key being part of internal branch.
	managedAddr, err := newManagedAddress(
		s, ImportedDerivationPath, wif.PrivKey, nil, wif.CompressPubKey,
		s.addrSchema.ExternalAddrType, nil,
	)
	if err != nil {
		return nil, err
	}
	managedAddr.imported = true

	// Add the new managed address to the cache of recent addresses and
	// return it.
	s.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr
	return managedAddr, nil
}

// toPublicManagedAddress converts an imported public key to an imported managed
// address.
func (s *ScopedKeyManager) toImportedPublicManagedAddress(
	pubKey *btcec.PublicKey, compressed bool) (*managedAddress, error) {

	// Create a new managed address based on the imported address.
	//
	// TODO: Handle imported key being part of internal branch.
	managedAddr, err := newManagedAddressWithoutPrivKey(
		s, ImportedDerivationPath, pubKey, nil, compressed,
		s.addrSchema.ExternalAddrType,
	)
	if err != nil {
		return nil, err
	}
	managedAddr.imported = true

	// Add the new managed address to the cache of recent addresses and
	// return it.
	s.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr
	return managedAddr, nil
}

// ImportScript imports a user-provided script into the address manager.  The
// imported script will act as a pay-to-script-hash address.
//
// All imported script addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// When the address manager is watching-only, the script itself will not be
// stored or available since it is considered private data.
//
// This function will return an error if the address manager is locked and not
// watching-only, or the address already exists.  Any other errors returned are
// generally unexpected.
func (s *ScopedKeyManager) ImportScript(ns walletdb.ReadWriteBucket,
	script []byte, bs *BlockStamp) (ManagedScriptAddress, error) {

	return s.importScriptAddress(
		ns, ScriptHashIdentity(script), script, bs, Script, 0, true,
	)
}

// ImportWitnessScript imports a user-provided script into the address manager.
// The imported script will act as a pay-to-witness-script-hash address.
//
// All imported script addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// When the address manager is watching-only, the script itself will not be
// stored or available since it is considered private data.
//
// This function will return an error if the address manager is locked and not
// watching-only, or the address already exists.  Any other errors returned are
// generally unexpected.
func (s *ScopedKeyManager) ImportWitnessScript(ns walletdb.ReadWriteBucket,
	script []byte, bs *BlockStamp, witnessVersion byte,
	isSecretScript bool) (ManagedScriptAddress, error) {

	return s.importScriptAddress(
		ns, WitnessScriptHashIdentity(script), script, bs,
		WitnessScript, witnessVersion, isSecretScript,
	)
}

// ImportTaprootScript imports a user-provided taproot script into the address
// manager. The imported script will act as a pay-to-taproot address.
func (s *ScopedKeyManager) ImportTaprootScript(ns walletdb.ReadWriteBucket,
	tapscript *Tapscript, bs *BlockStamp, witnessVersion byte,
	isSecretScript bool) (ManagedTaprootScriptAddress, error) {

	// Make sure we have everything we need to calculate the script root and
	// tweak the taproot key.
	taprootKey, err := tapscript.TaprootKey()
	if err != nil {
		return nil, fmt.Errorf("error calculating script root: %v", err)
	}

	script, err := tlvEncodeTaprootScript(tapscript)
	if err != nil {
		return nil, fmt.Errorf("error encoding taproot script: %v", err)
	}

	managedAddr, err := s.importScriptAddress(
		ns, TaprootIdentity(taprootKey), script, bs,
		TaprootScript, witnessVersion, isSecretScript,
	)
	if err != nil {
		return nil, err
	}

	// We know this is a taproot address at this point.
	return managedAddr.(ManagedTaprootScriptAddress), nil
}

// importScriptAddress imports a new pay-to-script or pay-to-witness-script
// address.
func (s *ScopedKeyManager) importScriptAddress(ns walletdb.ReadWriteBucket,
	identity Identity, script []byte, bs *BlockStamp, addrType AddressType,
	witnessVersion byte, isSecretScript bool) (ManagedScriptAddress,
	error) {

	s.rootManager.mtx.Lock()
	defer s.rootManager.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported script.
	if isSecretScript && s.rootManager.isLocked() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// A secret script can only be used with a non-watch only manager. If
	// a wallet is watch-only then the script must be encrypted with the
	// public encryption key.
	if isSecretScript && s.rootManager.watchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Prevent duplicates.
	scriptIdent := identity()
	alreadyExists := s.existsAddress(ns, scriptIdent)
	if alreadyExists {
		str := fmt.Sprintf("address for script hash/key %x already "+
			"exists", scriptIdent)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt the script hash/key using the crypto public key, so it is
	// accessible when the address manager is locked or watching-only.
	encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(scriptIdent)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt script hash/key %x",
			scriptIdent)
		return nil, managerError(ErrCrypto, str, err)
	}

	// If a key isn't considered to be "secret", we encrypt it with the
	// public key, so we can create script addresses that also work in
	// watch-only mode.
	cryptoKey := s.rootManager.cryptoKeyScript
	if !isSecretScript {
		cryptoKey = s.rootManager.cryptoKeyPub
	}

	// Encrypt the script for storage in database using the selected crypto
	// key.
	encryptedScript, err := cryptoKey.Encrypt(script)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt script for %x",
			scriptIdent)
		return nil, managerError(ErrCrypto, str, err)
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	updateStartBlock := false
	if bs.Height < s.rootManager.syncState.startBlock.Height {
		updateStartBlock = true
	}

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	switch addrType {
	case WitnessScript, TaprootScript:
		err = putWitnessScriptAddress(
			ns, &s.scope, scriptIdent, ImportedAddrAccount, ssNone,
			witnessVersion, isSecretScript, encryptedHash,
			encryptedScript,
		)

	default:
		err = putScriptAddress(
			ns, &s.scope, scriptIdent, ImportedAddrAccount, ssNone,
			encryptedHash, encryptedScript,
		)
	}
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	if updateStartBlock {
		err := putStartBlock(ns, bs)
		if err != nil {
			return nil, maybeConvertDbError(err)
		}
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		s.rootManager.syncState.startBlock = *bs
	}

	// Create a new managed address based on the imported script.  Also,
	// when not a watching-only address manager, make a copy of the script
	// since it will be cleared on lock and the script the caller passed
	// should not be cleared out from under the caller.
	var managedAddr ManagedScriptAddress
	switch addrType {
	case WitnessScript, TaprootScript:
		managedAddr, err = newWitnessScriptAddress(
			s, ImportedAddrAccount, scriptIdent, encryptedScript,
			witnessVersion, isSecretScript,
		)

	default:
		managedAddr, err = newScriptAddress(
			s, ImportedAddrAccount, scriptIdent, encryptedScript,
		)
	}
	if err != nil {
		return nil, err
	}

	// Even if the script is secret, we are currently unlocked, so we keep a
	// clear text copy of the script around to avoid decrypting it on each
	// access.
	if cts, ok := managedAddr.(clearTextScriptSetter); ok {
		cts.setClearTextScript(script)
	}

	// Add the new managed address to the cache of recent addresses and
	// return it.
	s.addrs[addrKey(scriptIdent)] = managedAddr
	return managedAddr, nil
}

// lookupAccount loads account number stored in the manager for the given
// account name
//
// This function MUST be called with the manager lock held for reads.
func (s *ScopedKeyManager) lookupAccount(ns walletdb.ReadBucket, name string) (uint32, error) {
	return fetchAccountByName(ns, &s.scope, name)
}

// LookupAccount loads account number stored in the manager for the given
// account name
func (s *ScopedKeyManager) LookupAccount(ns walletdb.ReadBucket, name string) (uint32, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	return s.lookupAccount(ns, name)
}

// fetchUsed returns true if the provided address id was flagged used.
func (s *ScopedKeyManager) fetchUsed(ns walletdb.ReadBucket,
	addressID []byte) bool {

	return fetchAddressUsed(ns, &s.scope, addressID)
}

// MarkUsed updates the used flag for the provided address.
func (s *ScopedKeyManager) MarkUsed(ns walletdb.ReadWriteBucket,
	address ltcutil.Address) error {

	addressID := address.ScriptAddress()
	err := markAddressUsed(ns, &s.scope, addressID)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Clear caches which might have stale entries for used addresses
	s.mtx.Lock()
	delete(s.addrs, addrKey(addressID))
	s.mtx.Unlock()
	return nil
}

// ChainParams returns the chain parameters for this address manager.
func (s *ScopedKeyManager) ChainParams() *chaincfg.Params {
	// NOTE: No need for mutex here since the net field does not change
	// after the manager instance is created.

	return s.rootManager.chainParams
}

// AccountName returns the account name for the given account number stored in
// the manager.
func (s *ScopedKeyManager) AccountName(ns walletdb.ReadBucket, account uint32) (string, error) {
	return fetchAccountName(ns, &s.scope, account)
}

// ForEachAccount calls the given function with each account stored in the
// manager, breaking early on error.
func (s *ScopedKeyManager) ForEachAccount(ns walletdb.ReadBucket,
	fn func(account uint32) error) error {

	return forEachAccount(ns, &s.scope, fn)
}

// LastAccount returns the last account stored in the manager.
// If no accounts, returns twos-complement representation of -1
func (s *ScopedKeyManager) LastAccount(ns walletdb.ReadBucket) (uint32, error) {
	return fetchLastAccount(ns, &s.scope)
}

// ForEachAccountAddress calls the given function with each address of the
// given account stored in the manager, breaking early on error.
func (s *ScopedKeyManager) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr ManagedAddress) error) error {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	return s.forEachAccountAddress(ns, account, fn)
}

func (s *ScopedKeyManager) forEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr ManagedAddress) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr)
	}
	err := forEachAccountAddress(ns, &s.scope, account, addrFn)
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// ForEachActiveAccountAddress calls the given function with each active
// address of the given account stored in the manager, breaking early on error.
//
// TODO(tuxcanfly): actually return only active addresses
func (s *ScopedKeyManager) ForEachActiveAccountAddress(ns walletdb.ReadBucket, account uint32,
	fn func(maddr ManagedAddress) error) error {

	return s.ForEachAccountAddress(ns, account, fn)
}

func (s *ScopedKeyManager) forEachActiveAccountAddress(ns walletdb.ReadBucket, account uint32,
	fn func(maddr ManagedAddress) error) error {

	return s.forEachAccountAddress(ns, account, fn)
}

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func (s *ScopedKeyManager) ForEachActiveAddress(ns walletdb.ReadBucket,
	fn func(addr ltcutil.Address) error) error {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	return s.forEachActiveAddress(ns, fn)
}

func (s *ScopedKeyManager) forEachActiveAddress(ns walletdb.ReadBucket,
	fn func(addr ltcutil.Address) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr.Address())
	}

	err := forEachActiveAddress(ns, &s.scope, addrFn)
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// ForEachInternalActiveAddress invokes the given closure on each _internal_
// active address belonging to the scoped key manager, breaking early on error.
func (s *ScopedKeyManager) ForEachInternalActiveAddress(ns walletdb.ReadBucket,
	fn func(addr ltcutil.Address) error) error {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	return s.forEachInternalActiveAddress(ns, fn)
}

func (s *ScopedKeyManager) forEachInternalActiveAddress(ns walletdb.ReadBucket,
	fn func(addr ltcutil.Address) error) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := s.rowInterfaceToManaged(ns, rowInterface)
		if err != nil {
			return err
		}
		// Skip any non-internal branch addresses.
		if !managedAddr.Internal() {
			return nil
		}
		return fn(managedAddr.Address())
	}

	if err := forEachActiveAddress(ns, &s.scope, addrFn); err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// IsWatchOnlyAccount determines if the given account belonging to this scoped
// manager is set up as watch-only.
func (s *ScopedKeyManager) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	account uint32) (bool, error) {

	s.rootManager.mtx.RLock()
	defer s.rootManager.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	acctInfo, err := s.loadAccountInfo(ns, account)
	if err != nil {
		return false, err
	}

	return acctInfo.acctKeyPriv == nil, nil
}

// cloneKeyWithVersion clones an extended key to use the version corresponding
// to the manager's key scope. This should only be used for non-watch-only
// accounts as they are stored within the database using the legacy BIP-0044
// version by default.
func (s *ScopedKeyManager) cloneKeyWithVersion(key *hdkeychain.ExtendedKey) (
	*hdkeychain.ExtendedKey, error) {

	// Determine the appropriate version based on the current network and
	// key scope.
	var version HDVersion
	net := s.rootManager.ChainParams().Net
	switch net {
	case wire.MainNet:
		switch s.scope {
		case KeyScopeBIP0044, KeyScopeBIP0086, KeyScopeMweb, KeyScopeLiteWallet:
			version = HDVersionMainNetBIP0044
		case KeyScopeBIP0049Plus:
			version = HDVersionMainNetBIP0049
		case KeyScopeBIP0084:
			version = HDVersionMainNetBIP0084
		default:
			return nil, fmt.Errorf("unsupported scope %v", s.scope)
		}

	case wire.TestNet, wire.TestNet4,
		netparams.SigNetWire(s.rootManager.ChainParams()):

		switch s.scope {
		case KeyScopeBIP0044, KeyScopeBIP0086, KeyScopeMweb, KeyScopeLiteWallet:
			version = HDVersionTestNetBIP0044
		case KeyScopeBIP0049Plus:
			version = HDVersionTestNetBIP0049
		case KeyScopeBIP0084:
			version = HDVersionTestNetBIP0084
		default:
			return nil, fmt.Errorf("unsupported scope %v", s.scope)
		}

	case wire.SimNet:
		switch s.scope {
		case KeyScopeBIP0044, KeyScopeBIP0086, KeyScopeMweb, KeyScopeLiteWallet:
			version = HDVersionSimNetBIP0044
		// We use the mainnet versions for simnet keys when the keys
		// belong to a key scope which simnet doesn't have a defined
		// version for.
		case KeyScopeBIP0049Plus:
			version = HDVersionMainNetBIP0049
		case KeyScopeBIP0084:
			version = HDVersionMainNetBIP0084
		default:
			return nil, fmt.Errorf("unsupported scope %v", s.scope)
		}

	default:
		return nil, fmt.Errorf("unsupported net %v", net)
	}

	var versionBytes [4]byte
	binary.BigEndian.PutUint32(versionBytes[:], uint32(version))

	return key.CloneWithVersion(versionBytes[:])
}

// InvalidateAccountCache invalidates the cache for the given account, forcing a
// database read to retrieve the account information.
func (s *ScopedKeyManager) InvalidateAccountCache(account uint32) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s.acctInfo, account)
}
