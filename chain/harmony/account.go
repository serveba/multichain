package harmony

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/harmony-one/harmony/core/types"
	"github.com/renproject/multichain/api/address"
	"github.com/renproject/multichain/api/contract"
	"github.com/renproject/pack"
)

// Tx represents a simple Harmony transaction
type Tx struct {
	HarmonyTx types.Transaction

	ChainID *big.Int
}

// Hash that uniquely identifies the transaction. Hashes are usually the
// result of an irreversible hashing function applied to some serialized
// representation of the transaction.
func (tx Tx) Hash() pack.Bytes {
	return pack.NewBytes(tx.HarmonyTx.Hash().Bytes())
}

// From returns the address from which value is being sent.
func (tx Tx) From() address.Address {
	return address.Address(fmt.Sprintf("%v", tx.HarmonyTx.From().Load()))
}

// To returns the address to which value is being sent.
func (tx Tx) To() address.Address {
	return address.Address(pack.NewString(tx.HarmonyTx.To().Hex()))
}

// Value being sent from one address to another.
func (tx Tx) Value() pack.U256 {
	return pack.NewU256FromInt(tx.HarmonyTx.Value())
}

// Nonce used to order the transaction with respect to all other
// transactions signed and submitted by the sender of this transaction.
func (tx Tx) Nonce() pack.U256 {
	return pack.NewU256FromInt(big.NewInt(int64(tx.HarmonyTx.Nonce())))
}

// Payload returns arbitrary data that is associated with the transaction.
// This payload is often used to send notes between external accounts, or
// call functions on a contract.
func (tx Tx) Payload() contract.CallData {
	return tx.HarmonyTx.Data()
}

// Sighashes that must be signed before the transaction can be submitted by
// the client.
func (tx Tx) Sighashes() ([]pack.Bytes32, error) {
	sighashes := make([]pack.Bytes32, 1)
	signer := types.NewEIP155Signer(tx.ChainID)
	signature := signer.Hash(&tx.HarmonyTx).Bytes()

	sighash := [32]byte{}
	copy(sighash[:], signature)
	sighashes[0] = pack.NewBytes32(sighash)

	return sighashes, nil
}

// Sign the transaction by injecting signatures for the required sighashes.
// The serialized public key used to sign the sighashes should also be
// specified whenever it is available.
func (tx Tx) Sign(signatures []pack.Bytes65, pubKey pack.Bytes) error {
	signer := types.NewEIP155Signer(tx.ChainID)
	// FIXME we have to retrieve somehow the private key in order to sign the TX
	key, _ := defaultTestKey()
	_, err := types.SignTx(&tx.HarmonyTx, signer, key)
	return err
}

// Temporary example
func defaultTestKey() (*ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

// Serialize the transaction into bytes. This is the format in which the
// transaction will be submitted by the client.
func (tx Tx) Serialize() (pack.Bytes, error) {
	return rlp.EncodeToBytes(tx.HarmonyTx)
}

// The TxBuilder interface defines the functionality required to build
// account-based transactions. Most chain implementations require additional
// information, and this should be accepted during the construction of the
// chain-specific transaction builder.
type TxBuilder struct {
}

func (txBuilder TxBuilder) BuildTx(from, to address.Address, value, nonce pack.U256, payload pack.Bytes) (Tx, error) {
	shardID := uint32(1)

	tx := types.NewTransaction(nonce.Int().Uint64(), common.BytesToAddress([]byte(to)),
		shardID, value.Int(), params.TxGas, nil, payload)

	// Note that we must include the Chain ID for the EIP115 signer; this can be fetched from the node's metadata
	return Tx{
		HarmonyTx: *tx,
		// FIXME
		ChainID: big.NewInt(0),
	}, nil
}

func (TxBuilder TxBuilder) FetchNonce() uint64 {
	// We may also want to include an additional method for TxBuilder to fetch the appropriate nonce for the BuildTx param
	// FIXME
	return uint64(0)
}

type Client struct {
}

// Tx returns the transaction uniquely identified by the given transaction
// hash. It also returns the number of confirmations for the transaction. If
// the transaction cannot be found before the context is done, or the
// transaction is invalid, then an error should be returned.
//
// Implementation Note:
// For the Client interface, the Tx method is simply a getTransactionByHash RPC call
func (Client) Tx(context.Context, pack.Bytes) (Tx, pack.U64, error) {
	// TODO
	return Tx{}, pack.NewU64(0), nil
}

// SubmitTx to the underlying chain. If the transaction cannot be found
// before the context is done, or the transaction is invalid, then an error
// should be returned.
//
// Implementation note:
// The SubmitTx method is not clear as to if it should block until confirmation of tx or not.
// Since most APIs do not block on the submission of a transaction, we should implement it as such
func (Client) SubmitTx(context.Context, Tx) error {
	// TODO
	return nil
}
