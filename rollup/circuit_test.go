/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rollup

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func TestGary2Oliver(t *testing.T) {

	operator := transfer4OneTime()

	verify(operator.witnesses)

}

func transfer4OneTime() Operator {
	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)

	receiver, err := operator.readAccount(1)

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)

	if err != nil {
	}
	return operator
}

func verify(witness Circuit) {
	var rollupCircuit Circuit

	for i := 0; i < BatchSizeCircuit; i++ {
		rollupCircuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	vr1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rollupCircuit)

	//2: generate R1CS
	pk, vk, _ := groth16.Setup(vr1cs)

	// verifies the proofs of inclusion of the transfer     [commit this to the chain]
	publicWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	//3: generate proof

	proof, err := groth16.Prove(vr1cs, pk, publicWitness)

	//4: verify proof [Contract OnChain]
	err = groth16.Verify(proof, vk, publicWitness)

	if err != nil {

	}
}
