// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txauthor provides transaction creation code for wallets.
package txauthor

import (
	"errors"
	"slices"

	"github.com/ltcsuite/ltcd/btcec/v2"
	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/ltcwallet/internal/zero"
	"github.com/ltcsuite/ltcwallet/waddrmgr"
	"github.com/ltcsuite/ltcwallet/wallet/txrules"
	"github.com/ltcsuite/ltcwallet/wallet/txsizes"
)

// SumOutputValues sums up the list of TxOuts and returns an Amount.
func SumOutputValues(outputs []*wire.TxOut) (totalOutput ltcutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += ltcutil.Amount(txOut.Value)
	}
	return totalOutput
}

// InputSource provides transaction inputs referencing spendable outputs to
// construct a transaction outputting some target amount.  If the target amount
// can not be satisified, this can be signaled by returning a total amount less
// than the target or by returning a more detailed error implementing
// InputSourceError.
type InputSource func(target ltcutil.Amount) (total ltcutil.Amount,
	inputs []*wire.TxIn, inputValues []ltcutil.Amount, scripts [][]byte,
	mwebOutputs []*wire.MwebOutput, err error)

// InputSourceError describes the failure to provide enough input value from
// unspent transaction outputs to meet a target amount.  A typed error is used
// so input sources can provide their own implementations describing the reason
// for the error, for example, due to spendable policies or locked coins rather
// than the wallet not having enough available input value.
type InputSourceError interface {
	error
	InputSourceError()
}

// Default implementation of InputSourceError.
type insufficientFundsError struct{}

func (insufficientFundsError) InputSourceError() {}
func (insufficientFundsError) Error() string {
	return "insufficient funds available to construct transaction"
}

// AuthoredTx holds the state of a newly-created transaction and the change
// output (if one was added).
type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []ltcutil.Amount
	PrevMwebOutputs []*wire.MwebOutput
	TotalInput      ltcutil.Amount
	ChangeIndex     int // negative if no change
	NewMwebCoins    []*mweb.Coin
}

// ChangeSource provides change output scripts for transaction creation.
type ChangeSource struct {
	// NewScript is a closure that produces unique change output scripts per
	// invocation.
	NewScript func(*waddrmgr.KeyScope) ([]byte, error)

	// ScriptSize is the size in bytes of scripts produced by `NewScript`.
	ScriptSize int
}

// NewUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs with
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2WPKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange is called zero or one times to generate this script.
// This function must return a P2WPKH script or smaller, otherwise fee estimation
// will be incorrect.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output any any necessary fees, an
// InputSourceError is returned.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func NewUnsignedTransaction(outputs []*wire.TxOut, feeRatePerKb ltcutil.Amount,
	fetchInputs InputSource, changeSource *ChangeSource) (*AuthoredTx, error) {

	targetAmount := SumOutputValues(outputs)
	estimatedSize := txsizes.EstimateVirtualSize(
		0, 0, 1, 0, outputs, changeSource.ScriptSize,
	)
	targetFee := txrules.FeeForSerializeSize(feeRatePerKb, estimatedSize)

	mwebFee := mweb.EstimateFee(outputs, feeRatePerKb, true)
	isMweb := slices.ContainsFunc(outputs, func(txOut *wire.TxOut) bool {
		return txscript.IsMweb(txOut.PkScript)
	})
	if isMweb {
		targetFee = ltcutil.Amount(mwebFee)
	}

	for {
		inputAmount, inputs, inputValues, scripts, mwebOutputs,
			err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			return nil, insufficientFundsError{}
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		var nested, p2wpkh, p2tr, mwebIn, p2pkh int
		for _, pkScript := range scripts {
			switch {
			// If this is a p2sh output, we assume this is a
			// nested P2WKH.
			case txscript.IsPayToScriptHash(pkScript):
				nested++
			case txscript.IsPayToWitnessPubKeyHash(pkScript):
				p2wpkh++
			case txscript.IsPayToTaproot(pkScript):
				p2tr++
			case txscript.IsMweb(pkScript):
				mwebIn++
			default:
				p2pkh++
			}
		}

		isMweb := isMweb || mwebIn > 0
		outputsToEstimate := outputs
		changeScriptSize := changeSource.ScriptSize
		if isMweb && mwebIn < len(inputs) {
			outputsToEstimate = []*wire.TxOut{mweb.NewPegin(
				uint64(inputAmount), &chainhash.Hash{})}
			changeScriptSize = 0
		}

		maxSignedSize := txsizes.EstimateVirtualSize(
			p2pkh, p2tr, p2wpkh, nested, outputsToEstimate, changeScriptSize,
		)
		if isMweb && mwebIn < len(inputs) {
			maxSignedSize += new(wire.TxIn).SerializeSize()
		}
		maxRequiredFee := txrules.FeeForSerializeSize(feeRatePerKb, maxSignedSize)

		var changeKeyScope *waddrmgr.KeyScope
		if isMweb {
			if mwebIn < len(inputs) {
				maxRequiredFee += ltcutil.Amount(mwebFee)
			} else {
				maxRequiredFee = ltcutil.Amount(mwebFee)
			}
			changeKeyScope = &waddrmgr.KeyScopeMweb
		}

		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTx{
			Version:  wire.TxVersion,
			TxIn:     inputs,
			TxOut:    outputs,
			LockTime: 0,
		}

		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		changeScript, err := changeSource.NewScript(changeKeyScope)
		if err != nil {
			return nil, err
		}
		change := wire.NewTxOut(int64(changeAmount), changeScript)
		if changeAmount != 0 && !txrules.IsDustOutput(change,
			txrules.DefaultRelayFeePerKb) || isMweb {

			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTx{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			PrevMwebOutputs: mwebOutputs,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}

// RandomizeOutputPosition randomizes the position of a transaction's output by
// swapping it with a random output.  The new index is returned.  This should be
// done before signing.
func RandomizeOutputPosition(outputs []*wire.TxOut, index int) int {
	r := cprng.Int31n(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}

// RandomizeChangePosition randomizes the position of an authored transaction's
// change output.  This should be done before signing.
func (tx *AuthoredTx) RandomizeChangePosition() {
	tx.ChangeIndex = RandomizeOutputPosition(tx.Tx.TxOut, tx.ChangeIndex)
}

// SecretsSource provides private keys and redeem scripts necessary for
// constructing transaction input signatures.  Secrets are looked up by the
// corresponding Address for the previous output script.  Addresses for lookup
// are created using the source's blockchain parameters and means a single
// SecretsSource can only manage secrets for a single chain.
//
// TODO: Rewrite this interface to look up private keys and redeem scripts for
// pubkeys, pubkey hashes, script hashes, etc. as separate interface methods.
// This would remove the ChainParams requirement of the interface and could
// avoid unnecessary conversions from previous output scripts to Addresses.
// This can not be done without modifications to the txscript package.
type SecretsSource interface {
	txscript.KeyDB
	txscript.ScriptDB
	ChainParams() *chaincfg.Params
	GetScanKey(ltcutil.Address) (*btcec.PrivateKey, error)
}

// AddAllInputScripts modifies transaction a transaction by adding inputs
// scripts for each input.  Previous output scripts being redeemed by each input
// are passed in prevPkScripts and the slice length must match the number of
// inputs.  Private keys and redeem scripts are looked up using a SecretsSource
// based on the previous output script.
func AddAllInputScripts(tx *wire.MsgTx, prevPkScripts [][]byte,
	inputValues []ltcutil.Amount, secrets SecretsSource) error {

	inputFetcher, err := TXPrevOutFetcher(tx, prevPkScripts, inputValues)
	if err != nil {
		return err
	}

	inputs := tx.TxIn
	hashCache := txscript.NewTxSigHashes(tx, inputFetcher)
	chainParams := secrets.ChainParams()

	if len(inputs) != len(prevPkScripts) {
		return errors.New("tx.TxIn and prevPkScripts slices must " +
			"have equal length")
	}

	for i := range inputs {
		pkScript := prevPkScripts[i]

		switch {
		// If this is a p2sh output, who's script hash pre-image is a
		// witness program, then we'll need to use a modified signing
		// function which generates both the sigScript, and the witness
		// script.
		case txscript.IsPayToScriptHash(pkScript):
			err := spendNestedWitnessPubKeyHash(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			err := spendWitnessKeyHash(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		case txscript.IsPayToTaproot(pkScript):
			err := spendTaprootKey(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		default:
			sigScript := inputs[i].SignatureScript
			script, err := txscript.SignTxOutput(chainParams, tx, i,
				pkScript, txscript.SigHashAll, secrets, secrets,
				sigScript)
			if err != nil {
				return err
			}
			inputs[i].SignatureScript = script
		}
	}

	return nil
}

// spendWitnessKeyHash generates, and sets a valid witness for spending the
// passed pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0143 includes
// the input value in the sighash.
func spendWitnessKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2wkh address.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	// Once we have the key pair, generate a p2wkh address type, respecting
	// the compression type of the generated key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = ltcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = ltcutil.Hash160(pubKey.SerializeUncompressed())
	}
	p2wkhAddr, err := ltcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}

	// With the concrete address type, we can now generate the
	// corresponding witness program to be used to generate a valid witness
	// which will allow us to spend this output.
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, true)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendTaprootKey generates, and sets a valid witness for spending the passed
// pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0341 includes
// the input value in the sighash.
func spendTaprootKey(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2tr address. If the
	// pkScript is incorrect or derived from a different internal key or
	// with a script root, we simply won't find a corresponding private key
	// here.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, chainParams)
	if err != nil {
		return err
	}
	privKey, _, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}

	// We can now generate a valid witness which will allow us to spend this
	// output.
	witnessScript, err := txscript.TaprootWitnessSignature(
		tx, hashCache, idx, inputValue, pkScript,
		txscript.SigHashDefault, privKey,
	)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendNestedWitnessPubKey generates both a sigScript, and valid witness for
// spending the passed pkScript with the specified input amount. The generated
// sigScript is the version 0 p2wkh witness program corresponding to the queried
// key. The witness stack is identical to that of one which spends a regular
// p2wkh output. The input amount *must* correspond to the output value of the
// previous pkScript, or else verification will fail since the new sighash
// digest algorithm defined in BIP0143 includes the input value in the sighash.
func spendNestedWitnessPubKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First we need to obtain the key pair related to this p2sh output.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	var pubKeyHash []byte
	if compressed {
		pubKeyHash = ltcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = ltcutil.Hash160(pubKey.SerializeUncompressed())
	}

	// Next, we'll generate a valid sigScript that'll allow us to spend
	// the p2sh output. The sigScript will contain only a single push of
	// the p2wkh witness program corresponding to the matching public key
	// of this address.
	p2wkhAddr, err := ltcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err := bldr.Script()
	if err != nil {
		return err
	}
	txIn.SignatureScript = sigScript

	// With the sigScript in place, we'll next generate the proper witness
	// that'll allow us to spend the p2wkh output.
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, compressed)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// AddAllInputScripts modifies an authored transaction by adding inputs scripts
// for each input of an authored transaction.  Private keys and redeem scripts
// are looked up using a SecretsSource based on the previous output script.
func (tx *AuthoredTx) AddAllInputScripts(secrets SecretsSource) error {
	return AddAllInputScripts(
		tx.Tx, tx.PrevScripts, tx.PrevInputValues, secrets,
	)
}

// TXPrevOutFetcher creates a txscript.PrevOutFetcher from a given slice of
// previous pk scripts and input values.
func TXPrevOutFetcher(tx *wire.MsgTx, prevPkScripts [][]byte,
	inputValues []ltcutil.Amount) (*txscript.MultiPrevOutFetcher, error) {

	if len(tx.TxIn) != len(prevPkScripts) {
		return nil, errors.New("tx.TxIn and prevPkScripts slices " +
			"must have equal length")
	}
	if len(tx.TxIn) != len(inputValues) {
		return nil, errors.New("tx.TxIn and inputValues slices " +
			"must have equal length")
	}

	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for idx, txin := range tx.TxIn {
		fetcher.AddPrevOut(txin.PreviousOutPoint, &wire.TxOut{
			Value:    int64(inputValues[idx]),
			PkScript: prevPkScripts[idx],
		})
	}

	return fetcher, nil
}

func (tx *AuthoredTx) AddMweb(secrets SecretsSource,
	feeRatePerKb ltcutil.Amount) (err error) {

	var (
		chainParams = secrets.ChainParams()
		txIns       []*wire.TxIn
		pegouts     []*wire.TxOut
		coins       []*mweb.Coin
		recipients  []*mweb.Recipient
		prevScripts [][]byte
		prevValues  []ltcutil.Amount
		sumCoins    uint64
		sumOutputs  uint64
	)

	for i, txIn := range tx.Tx.TxIn {
		if !txscript.IsMweb(tx.PrevScripts[i]) {
			txIns = append(txIns, txIn)
			prevScripts = append(prevScripts, tx.PrevScripts[i])
			prevValues = append(prevValues, tx.PrevInputValues[i])
			continue
		}
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			tx.PrevScripts[i], chainParams)
		if err != nil {
			return err
		}
		scanKeyPriv, err := secrets.GetScanKey(addrs[0])
		if err != nil {
			return err
		}
		defer scanKeyPriv.Zero()
		scanSecret := (*mw.SecretKey)(scanKeyPriv.Serialize())
		defer zero.Bytes(scanSecret[:])

		coin, err := mweb.RewindOutput(tx.PrevMwebOutputs[i], scanSecret)
		if err != nil {
			return err
		}
		coins = append(coins, coin)
		sumCoins += coin.Value

		spendKeyPriv, _, err := secrets.GetKey(addrs[0])
		if err != nil {
			return err
		}
		defer spendKeyPriv.Zero()
		spendSecret := (*mw.SecretKey)(spendKeyPriv.Serialize())
		defer zero.Bytes(spendSecret[:])

		coin.CalculateOutputKey(spendSecret)
	}

	for _, txOut := range tx.Tx.TxOut {
		sumOutputs += uint64(txOut.Value)
		if !txscript.IsMweb(txOut.PkScript) {
			pegouts = append(pegouts, txOut)
			continue
		}
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, chainParams)
		if err != nil {
			return err
		}
		recipients = append(recipients, &mweb.Recipient{
			Value:   uint64(txOut.Value),
			Address: addrs[0].(*ltcutil.AddressMweb).StealthAddress(),
		})
	}

	if len(coins) == 0 && len(recipients) == 0 {
		return
	}

	var fee, pegin uint64
	if len(txIns) > 0 {
		fee = mweb.EstimateFee(tx.Tx.TxOut, feeRatePerKb, false)
		pegin = sumOutputs + fee - sumCoins
	} else {
		fee = sumCoins - sumOutputs
	}

	tx.Tx.Mweb, tx.NewMwebCoins, err =
		mweb.NewTransaction(coins, recipients, fee, pegin, pegouts)
	if err != nil {
		return err
	}

	tx.Tx.TxIn = txIns
	tx.Tx.TxOut = nil
	tx.PrevScripts = prevScripts
	tx.PrevInputValues = prevValues
	tx.ChangeIndex = -1

	if pegin > 0 {
		tx.Tx.AddTxOut(mweb.NewPegin(pegin, tx.Tx.Mweb.TxBody.Kernels[0].Hash()))
	}

	return
}
