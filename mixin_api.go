package main

import (
	_"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	_"errors"
	"fmt"
	_"net/http"
	_"os"
	"strconv"
	"strings"
	_"time"
	"runtime"
	"log"
	"C"

	"github.com/MixinNetwork/mixin/common"
	_"github.com/MixinNetwork/mixin/config"
	"github.com/MixinNetwork/mixin/crypto"
	_"github.com/MixinNetwork/mixin/kernel"
	_"github.com/MixinNetwork/mixin/storage"
	_"github.com/urfave/cli/v2"
)

type CreateAddressResult struct {
	Address string `json:"address"`
	ViewKey string `json:"view_key"`
	SpendKey string `json:"spend_key"`
}

type CreateAddressParams struct {
	ViewKey string `json:"view_key"`
	SpendKey string `json:"spend_key"`
	Public bool `json:"public"`
}

func renderData(data interface{}) *C.char {
	ret := map[string]interface{}{"data": data}
	result, _ := json.Marshal(ret)
	return C.CString(string(result))
}

func renderError(err error) *C.char {
	pc, fn, line, _ := runtime.Caller(1)
	error := fmt.Sprintf("[error] in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), fn, line, err)
	ret := map[string]interface{}{"error": error}
	result, _ := json.Marshal(ret)
	return C.CString(string(result))
}

//export Init
func Init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

//export CreateAddress
func CreateAddress(_params *C.char) *C.char {
	var params CreateAddressParams
	__params := C.GoString(_params)
	err := json.Unmarshal([]byte(__params), &params)
	if err != nil {
		return renderData(err)
	}

	seed := make([]byte, 64)
	_, err = rand.Read(seed)
	if err != nil {
		return renderError(err)
	}
	addr := common.NewAddressFromSeed(seed)
	if len(params.ViewKey) > 0 {
		key, err := hex.DecodeString(params.ViewKey)
		if err != nil {
			return renderError(err)
		}
		copy(addr.PrivateViewKey[:], key)
		addr.PublicViewKey = addr.PrivateViewKey.Public()
	}
	if len(params.SpendKey) > 0 {
		key, err := hex.DecodeString(params.SpendKey)
		if err != nil {
			return renderError(err)
		}
		copy(addr.PrivateSpendKey[:], key)
		addr.PublicSpendKey = addr.PrivateSpendKey.Public()
	}
	if params.Public {
		addr.PrivateViewKey = addr.PublicSpendKey.DeterministicHashDerive()
		addr.PublicViewKey = addr.PrivateViewKey.Public()
	}
	var result CreateAddressResult

	// fmt.Printf("address:\t%s\n", addr.String())
	// fmt.Printf("view key:\t%s\n", addr.PrivateViewKey.String())
	// fmt.Printf("spend key:\t%s\n", addr.PrivateSpendKey.String())

	result.ViewKey = addr.PrivateViewKey.String()
	result.SpendKey = addr.PrivateSpendKey.String()
	result.Address = addr.String()
	return renderData(result)
}

//export DecodeAddress
func DecodeAddress(_address *C.char) *C.char {
	address := C.GoString(_address)
	addr, err := common.NewAddressFromString(address)
	if err != nil {
		return renderError(err)
	}

	data := map[string]string{}

	// fmt.Printf("public view key:\t%s\n", addr.PublicViewKey.String())
	// fmt.Printf("public spend key:\t%s\n", addr.PublicSpendKey.String())
	// fmt.Printf("spend derive private:\t%s\n", addr.PublicSpendKey.DeterministicHashDerive())
	// fmt.Printf("spend derive public:\t%s\n", addr.PublicSpendKey.DeterministicHashDerive().Public())

	data["public_view_key"] = addr.PublicViewKey.String()
	data["public_spend_key"] = addr.PublicSpendKey.String()
	data["private_spend_key_derive"] = fmt.Sprintf("%s", addr.PublicSpendKey.DeterministicHashDerive())
	data["public_spend_key_derive"] = fmt.Sprintf("%s", addr.PublicSpendKey.DeterministicHashDerive().Public())
	return renderData(data)
}

//export DecodeSignature
func DecodeSignature(_signature *C.char) *C.char {
	var s struct{ S crypto.CosiSignature }

	in := fmt.Sprintf(`{"S":"%s"}`, C.GoString(_signature))
	err := json.Unmarshal([]byte(in), &s)
	if err != nil {
		return renderError(err)
	}

	data := map[string]string{}
	data["signers"] = fmt.Sprintf("%v", s.S.Keys())
	data["threshold"] = fmt.Sprintf("%d", len(s.S.Keys()))
	return renderData(data)
}

//export DecryptGhost
func DecryptGhost(_ghostKey *C.char) *C.char {
	__ghostKey := C.GoString(_ghostKey)
	var ghostKey map[string]string
	if err := json.Unmarshal([]byte(__ghostKey), &ghostKey); err != nil {
		return renderError(err)
	}

	view, err := crypto.KeyFromString(ghostKey["view"])
	if err != nil {
		return renderError(err)
	}

	key, err := crypto.KeyFromString(ghostKey["key"])
	if err != nil {
		return renderError(err)
	}

	mask, err := crypto.KeyFromString(ghostKey["mask"])
	if err != nil {
		return renderError(err)
	}

	n, err := strconv.ParseUint(ghostKey["index"], 10, 64)
	if err != nil {
		return renderError(err)
	}
	spend := crypto.ViewGhostOutputKey(&key, &view, &mask, n)
	addr := common.Address{
		PublicViewKey:  view.Public(),
		PublicSpendKey: *spend,
	}
	return renderData(addr.String())
}

//export DecodeTransaction
func DecodeTransaction(_raw *C.char) *C.char {
	__raw := C.GoString(_raw)
	raw, err := hex.DecodeString(__raw)
	if err != nil {
		return renderError(err)
	}
	ver, err := common.UnmarshalVersionedTransaction(raw)
	if err != nil {
		return renderError(err)
	}
	m := transactionToMap(ver)
	data, err := json.Marshal(m)
	if err != nil {
		return renderError(err)
	}
	return renderData(string(data))
}

//export EncodeTransaction
func EncodeTransaction(params *C.char, signs *C.char) *C.char {
	var trx common.SignedTransaction

	err := json.Unmarshal([]byte(C.GoString(params)), &trx)
	if err != nil {
		return renderError(err)
	}

	err = json.Unmarshal([]byte(C.GoString(signs)), &trx.SignaturesMap)
	if err != nil {
		return renderError(err)
	}
	
	signed := trx.AsLatestVersion()
	return renderData(hex.EncodeToString(signed.Marshal()))
}

//export SignRawTransaction
func SignRawTransaction(_params *C.char) *C.char {
	var params map[string]string
	err := json.Unmarshal([]byte(C.GoString(_params)), &params)
	if err != nil {
		return renderError(err)
	}

	_raw, err := hex.DecodeString(params["raw"])
	if err != nil {
		return renderError(err)
	}
	ver, err := common.UnmarshalVersionedTransaction(_raw)
	if err != nil {
		return renderError(err)
	}

	var raw = signerInput{}
	err = json.Unmarshal([]byte(params["trx"]), &raw)
	raw.Node = params["node"]

	var keys []string
	if err = json.Unmarshal([]byte(params["keys"]), &keys); err != nil {
		return renderError(err)
	}
	
	var accounts []*common.Address
	for _, s := range keys {
		key, err := hex.DecodeString(s)
		if err != nil {
			return renderError(err)
		}
		if len(key) != 64 {
			return renderError(fmt.Errorf("invalid key length %d", len(key)))
		}
		var account common.Address
		copy(account.PrivateViewKey[:], key[:32])
		copy(account.PrivateSpendKey[:], key[32:])
		accounts = append(accounts, &account)
	}
	
	inputIndex, err := strconv.ParseInt(params["input_index"], 10, 64)
	if err != nil {
		return renderError(err)
	}

	ver.SignaturesMap = nil

	err = ver.SignInput(raw, int(inputIndex), accounts)
	if err != nil {
		return renderError(err)
	}
	log.Printf("++++++++++ver.SignaturesMap: %v", ver.SignaturesMap)
	signatures, err := json.Marshal(ver.SignaturesMap)
	if err != nil {
		return renderError(err)
	}

	return renderData(string(signatures))
}

//export AddSignaturesToRawTransaction
func AddSignaturesToRawTransaction(_raw *C.char, signs *C.char) *C.char {
	raw, err := hex.DecodeString(C.GoString(_raw))
	if err != nil {
		return renderError(err)
	}
	ver, err := common.UnmarshalVersionedTransaction(raw)
	if err != nil {
		return renderError(err)
	}

	err = json.Unmarshal([]byte(C.GoString(signs)), &ver.SignaturesMap)

	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(ver.Marshal()))
}

//export BuildRawTransaction
func BuildRawTransaction(_params *C.char) *C.char {
	var params map[string]string
	
	if err := json.Unmarshal([]byte(C.GoString(_params)), &params); err != nil {
		return renderError(err)
	}

	seed, err := hex.DecodeString(params["seed"])
	if err != nil {
		return renderError(err)
	}
	if len(seed) != 64 {
		seed = make([]byte, 64)
		_, err := rand.Read(seed)
		if err != nil {
			return renderError(err)
		}
	}

	viewKey, err := crypto.KeyFromString(params["view"])
	if err != nil {
		return renderError(err)
	}
	spendKey, err := crypto.KeyFromString(params["spend"])
	if err != nil {
		return renderError(err)
	}
	account := common.Address{
		PrivateViewKey:  viewKey,
		PrivateSpendKey: spendKey,
		PublicViewKey:   viewKey.Public(),
		PublicSpendKey:  spendKey.Public(),
	}

	asset, err := crypto.HashFromString(params["asset"])
	if err != nil {
		return renderError(err)
	}

	extra, err := hex.DecodeString(params["extra"])
	if err != nil {
		return renderError(err)
	}

	inputs := make([]map[string]interface{}, 0)
	for _, in := range strings.Split(params["inputs"], ",") {
		parts := strings.Split(in, ":")
		if len(parts) != 2 {
			return renderError(fmt.Errorf("invalid input %s", in))
		}
		hash, err := crypto.HashFromString(parts[0])
		if err != nil {
			return renderError(err)
		}
		index, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return renderError(err)
		}
		inputs = append(inputs, map[string]interface{}{
			"hash":  hash,
			"index": int(index),
		})
	}

	outputs := make([]map[string]interface{}, 0)
	for _, out := range strings.Split(params["outputs"], ",") {
		parts := strings.Split(out, ":")
		if len(parts) != 2 {
			return renderError(fmt.Errorf("invalid output %s", out))
		}
		addr, err := common.NewAddressFromString(parts[0])
		if err != nil {
			return renderError(err)
		}
		amount := common.NewIntegerFromString(parts[1])
		if amount.Sign() == 0 {
			return renderError(fmt.Errorf("invalid output %s", out))
		}
		outputs = append(outputs, map[string]interface{}{
			"accounts": []*common.Address{&addr},
			"amount":   amount,
		})
	}

	var raw signerInput
	raw.Node = params["node"]
	isb, _ := json.Marshal(map[string]interface{}{"inputs": inputs})
	
	if err := json.Unmarshal(isb, &raw); err != nil {
		return renderError(err)
	}

	tx := common.NewTransaction(asset)
	for _, in := range inputs {
		tx.AddInput(in["hash"].(crypto.Hash), in["index"].(int))
	}
	for _, out := range outputs {
		tx.AddScriptOutput(out["accounts"].([]*common.Address), common.NewThresholdScript(1), out["amount"].(common.Integer), seed)
	}
	tx.Extra = extra

	signed := tx.AsLatestVersion()
	for i := range tx.Inputs {
		err = signed.SignInput(raw, i, []*common.Address{&account})
		if err != nil {
			return renderError(err)
		}
	}
	return renderData(hex.EncodeToString(signed.Marshal()))
}

//export SignTransaction
func SignTransaction(_params *C.char) *C.char {
	var raw signerInput
	var params map[string]string

	if err := json.Unmarshal([]byte(C.GoString(_params)), &params); err != nil {
		return renderError(err)
	}

	err := json.Unmarshal([]byte(params["raw"]), &raw)
	if err != nil {
		return renderError(err)
	}
	raw.Node = params["node"]

	seed, err := hex.DecodeString(params["seed"])
	if err != nil {
		return renderError(err)
	}
	if len(seed) != 64 {
		seed = make([]byte, 64)
		_, err := rand.Read(seed)
		if err != nil {
			return renderError(err)
		}
	}

	tx := common.NewTransaction(raw.Asset)
	for _, in := range raw.Inputs {
		if d := in.Deposit; d != nil {
			tx.AddDepositInput(&common.DepositData{
				Chain:           d.Chain,
				AssetKey:        d.AssetKey,
				TransactionHash: d.TransactionHash,
				OutputIndex:     d.OutputIndex,
				Amount:          d.Amount,
			})
		} else {
			tx.AddInput(in.Hash, in.Index)
		}
	}

	for _, out := range raw.Outputs {
		if out.Mask.HasValue() {
			tx.Outputs = append(tx.Outputs, &common.Output{
				Type:   out.Type,
				Amount: out.Amount,
				Keys:   out.Keys,
				Script: out.Script,
				Mask:   out.Mask,
			})
		}  else if out.Withdrawal != nil {
			tx.Outputs = append(tx.Outputs, &common.Output{
				Amount:     out.Amount,
				Withdrawal: out.Withdrawal,
				Type:       out.Type,
			})
		} else {
			hash := crypto.NewHash(seed)
			seed = append(hash[:], hash[:]...)
			tx.AddOutputWithType(out.Type, out.Accounts, out.Script, out.Amount, seed)
		}
	}

	extra, err := hex.DecodeString(raw.Extra)
	if err != nil {
		return renderError(err)
	}
	tx.Extra = extra

	var keys []string
	if err = json.Unmarshal([]byte(params["key"]), &keys); err != nil {
		return renderError(err)
	}

	var accounts []*common.Address
	for _, s := range keys {
		key, err := hex.DecodeString(s)
		if err != nil {
			return renderError(err)
		}
		if len(key) != 64 {
			return renderError(fmt.Errorf("invalid key length %d", len(key)))
		}
		var account common.Address
		copy(account.PrivateViewKey[:], key[:32])
		copy(account.PrivateSpendKey[:], key[32:])
		accounts = append(accounts, &account)
	}

	signed := tx.AsLatestVersion()
	inputIndex, err := strconv.ParseInt(params["inputIndex"], 10, 64)
	if err != nil {
		return renderError(err)
	}
	err = signed.SignInput(raw, int(inputIndex), accounts)
	if err != nil {
		return renderError(err)
	}

	signatures, err := json.Marshal(signed.SignaturesMap)
	if err != nil {
		return renderError(err)
	}

	var ret = map[string]string{}
	ret["signature"] = string(signatures)
	ret["raw"] = hex.EncodeToString(signed.Marshal())

	return renderData(ret)
}

//export PledgeNode
func PledgeNode(_params *C.char) *C.char {
	var params map[string]string

	if err := json.Unmarshal([]byte(C.GoString(_params)), &params); err != nil {
		return renderError(err)
	}
	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		return renderError(err)
	}
	viewKey, err := crypto.KeyFromString(params["view"])
	if err != nil {
		return renderError(err)
	}
	spendKey, err := crypto.KeyFromString(params["spend"])
	if err != nil {
		return renderError(err)
	}
	account := common.Address{
		PrivateViewKey:  viewKey,
		PrivateSpendKey: spendKey,
		PublicViewKey:   viewKey.Public(),
		PublicSpendKey:  spendKey.Public(),
	}

	signer, err := common.NewAddressFromString(params["signer"])
	if err != nil {
		return renderError(err)
	}
	payee, err := common.NewAddressFromString(params["payee"])
	if err != nil {
		return renderError(err)
	}

	var raw signerInput
	input, err := crypto.HashFromString(params["input"])
	if err != nil {
		return renderError(err)
	}
	err = json.Unmarshal([]byte(fmt.Sprintf(`{"inputs":[{"hash":"%s","index":0}]}`, input.String())), &raw)
	if err != nil {
		return renderError(err)
	}
	raw.Node = params["node"]

	amount := common.NewIntegerFromString(params["amount"])

	tx := common.NewTransaction(common.XINAssetId)
	tx.AddInput(input, 0)
	tx.AddOutputWithType(common.OutputTypeNodePledge, nil, common.Script{}, amount, seed)
	tx.Extra = append(signer.PublicSpendKey[:], payee.PublicSpendKey[:]...)

	signed := tx.AsLatestVersion()
	err = signed.SignInput(raw, 0, []*common.Address{&account})
	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(signed.Marshal()))
}

//export CancelNode
func CancelNode(_params *C.char) *C.char {
	var params map[string]string
	if err := json.Unmarshal([]byte(C.GoString(_params)), &params); err != nil {
		return renderError(err)
	}
	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		return renderError(err)
	}
	viewKey, err := crypto.KeyFromString(params["view"])
	if err != nil {
		return renderError(err)
	}
	spendKey, err := crypto.KeyFromString(params["spend"])
	if err != nil {
		return renderError(err)
	}
	receiver, err := common.NewAddressFromString(params["receiver"])
	if err != nil {
		return renderError(err)
	}
	account := common.Address{
		PrivateViewKey:  viewKey,
		PrivateSpendKey: spendKey,
		PublicViewKey:   viewKey.Public(),
		PublicSpendKey:  spendKey.Public(),
	}
	if account.String() != receiver.String() {
		return renderError(fmt.Errorf("invalid key and receiver %s %s", account, receiver))
	}

	b, err := hex.DecodeString(params["pledge"])
	if err != nil {
		return renderError(err)
	}
	pledge, err := common.UnmarshalVersionedTransaction(b)
	if err != nil {
		return renderError(err)
	}
	if pledge.TransactionType() != common.TransactionTypeNodePledge {
		err = fmt.Errorf("invalid pledge transaction type %d", pledge.TransactionType())
		return renderError(err)
	}

	b, err = hex.DecodeString(params["source"])
	if err != nil {
		return renderError(err)
	}
	source, err := common.UnmarshalVersionedTransaction(b)
	if err != nil {
		return renderError(err)
	}
	if source.TransactionType() != common.TransactionTypeScript {
		err = fmt.Errorf("invalid source transaction type %d", source.TransactionType())
		return renderError(err)
	}

	if source.PayloadHash() != pledge.Inputs[0].Hash {
		err = fmt.Errorf("invalid source transaction hash %s %s", source.PayloadHash(), pledge.Inputs[0].Hash)
		return renderError(err)
	}
	if len(source.Outputs) != 1 || len(source.Outputs[0].Keys) != 1 {
		err = fmt.Errorf("invalid source transaction outputs %d %d", len(source.Outputs), len(source.Outputs[0].Keys))
		return renderError(err)
	}
	pig := crypto.ViewGhostOutputKey(&source.Outputs[0].Keys[0], &viewKey, &source.Outputs[0].Mask, 0)
	if pig.String() != receiver.PublicSpendKey.String() {
		err = fmt.Errorf("invalid source and receiver %s %s", pig.String(), receiver.PublicSpendKey)
		return renderError(err)
	}

	tx := common.NewTransaction(common.XINAssetId)
	tx.AddInput(pledge.PayloadHash(), 0)
	tx.AddOutputWithType(common.OutputTypeNodeCancel, nil, common.Script{}, pledge.Outputs[0].Amount.Div(100), seed)
	tx.AddScriptOutput([]*common.Address{&receiver}, common.NewThresholdScript(1), pledge.Outputs[0].Amount.Sub(tx.Outputs[0].Amount), seed)
	tx.Extra = append(pledge.Extra, viewKey[:]...)
	utxo := &common.UTXO{
		Input: common.Input{
			Hash:  pledge.PayloadHash(),
			Index: 0,
		},
		Output: common.Output{
			Type: common.OutputTypeNodePledge,
			Keys: source.Outputs[0].Keys,
			Mask: source.Outputs[0].Mask,
		},
	}
	signed := tx.AsLatestVersion()
	err = signed.SignUTXO(utxo, []*common.Address{&account})
	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(signed.Marshal()))
}

//export DecodePledgeNode
func DecodePledgeNode(_params *C.char) *C.char {
	var params map[string]string
	if err := json.Unmarshal([]byte(C.GoString(_params)), &params); err != nil {
		return renderError(err)
	}
	b, err := hex.DecodeString(params["raw"])
	if err != nil {
		return renderError(err)
	}
	pledge, err := common.UnmarshalVersionedTransaction(b)
	if err != nil {
		return renderError(err)
	}
	if len(pledge.Extra) != len(crypto.Key{})*2 {
		return renderError(fmt.Errorf("invalid extra %s", hex.EncodeToString(pledge.Extra)))
	}
	signerPublicSpend, err := crypto.KeyFromString(hex.EncodeToString(pledge.Extra[:32]))
	if err != nil {
		return renderError(err)
	}
	payeePublicSpend, err := crypto.KeyFromString(hex.EncodeToString(pledge.Extra[32:]))
	if err != nil {
		return renderError(err)
	}
	signer := common.Address{
		PublicSpendKey: signerPublicSpend,
		PublicViewKey:  signerPublicSpend.DeterministicHashDerive().Public(),
	}
	payee := common.Address{
		PublicSpendKey: payeePublicSpend,
		PublicViewKey:  payeePublicSpend.DeterministicHashDerive().Public(),
	}
	var result map[string]string
	result["signer"] = fmt.Sprintf("%s", signer)
	result["payee"] = fmt.Sprintf("%s", payee)
	return renderData(result)
}

type GhostKeys struct {
	Mask crypto.Key   `json:"mask"`
	Keys []crypto.Key `json:"keys"`
}

//export BuildTransactionWithGhostKeys
func BuildTransactionWithGhostKeys(assetId_ *C.char, ghostKeys_ *C.char, trxHash_ *C.char, outputAmount_ *C.char, memo_ *C.char, outputIndex_ int) *C.char {
	assetId := C.GoString(assetId_)
	ghostKeys := C.GoString(ghostKeys_)
	trxHash := C.GoString(trxHash_)
	outputAmount := C.GoString(outputAmount_)
	memo := C.GoString(memo_)

	var keys []GhostKeys
	err := json.Unmarshal([]byte(ghostKeys), &keys)
	if err != nil {
		return renderError(err)
	}

	var amounts []string
	err = json.Unmarshal([]byte(outputAmount), &amounts)
	if err != nil {
		return renderError(err)
	}

	if len(keys) != len(amounts) {
		return renderError(err)
	}
	
	var outputs []*common.Output;
	for i, key := range keys {
		output := &common.Output{Mask: key.Mask, Keys: key.Keys, Amount: common.NewIntegerFromString(amounts[i]), Script: []uint8("\xff\xfe\x01")}
		outputs = append(outputs, output)
	}

	_assetId, err := crypto.HashFromString(assetId)
	if err != nil {
		return renderError(err)
	}

	_memo, err := hex.DecodeString(memo)
	if err != nil {
		return renderError(err)
	}

	_trxHash, err := crypto.HashFromString(trxHash)
	if err != nil {
		return renderError(err)
	}

	tx := &common.Transaction {
		Version: common.TxVersion,
		Inputs:  []*common.Input{&common.Input{Hash: _trxHash, Index: outputIndex_}},
//		Outputs: []*Output{&Output{Mask: keys.Mask, Keys: keys.Keys, Amount: outputAmount, Script: "fffe01"}},
		Outputs: outputs,
		Asset: _assetId,
		Extra: _memo,
	}
	signed := tx.AsLatestVersion()
	return renderData(hex.EncodeToString(signed.Marshal()))
}

//export GetPublicKey
func GetPublicKey(_private *C.char) *C.char {
	private := C.GoString(_private)
	key, err := crypto.KeyFromString(private)
	if err != nil {
		return renderError(err)
	}
	return renderData(key.Public())
}
