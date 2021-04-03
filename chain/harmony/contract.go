package harmony

import (
	"context"
	"fmt"

	"github.com/renproject/multichain/api/address"
	"github.com/renproject/pack"
)

type Caller struct {
}

// CallContract at the specified address, using the specified calldata as
// input (this encodes the function and its parameters). The function output
// is returned as raw uninterpreted bytes. It is up to the application to
// interpret these bytes in a meaningful way.  If the call cannot be
// completed before the context is done, or the call is invalid, then an
// error should be returned.
func (c Caller) CallContract(ctx context.Context, a address.Address, callData []byte) (pack.Bytes, error) {
	// https://api.hmny.io/?version=latest#d34b1f82-9b29-4b68-bac7-52fa0a8884b1
	const method = "hmyv2_call"
	// FIXME get URL ctx func param
	url := "https://rpc.s0.t.hmny.io"
	// FIXME get hash from pack.Bytes func param
	txHash := "0x41d6e74ff3a7e615080b98fcfb7bce8be7b1ba4a8671e1ba2e9527eb3e1da20d"
	data := []byte(fmt.Sprintf("[\"%s\"]", txHash))
	_, err := SendData(method, data, url)

	return nil, err
}
