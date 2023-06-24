package pk_cs_generate

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"testing"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {

	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func SetCircuit() (circuit Circuit) {
	circuit = Circuit{
		X: 1,
		Y: 7,
	}
	return circuit
}

func Test_Pk_Vk_Generate(t *testing.T) {

	var circuit Circuit
	//1: execute Transaction ,

	vr1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	circuit = SetCircuit()
	//2: generate R1CS
	pk, vk, _ := groth16.Setup(vr1cs)

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(vr1cs, pk, witness)

	//4: verify proof [Contract OnChain]
	err = groth16.Verify(proof, vk, witness)
	if err != nil {
	}

	write2File(vr1cs, pk, proof, vk)

}

func write2File(vr1cs constraint.ConstraintSystem, pk groth16.ProvingKey, proof groth16.Proof, vk groth16.VerifyingKey) {

	vk_file, err := os.Create(fmt.Sprintf("%s.txt", "vk_Input_1"))
	if err != nil {
	}
	vk.ExportSolidity(vk_file)

	// R1CS implements io.WriterTo and io.ReaderFrom
	var buf bytes.Buffer
	_, _ = vr1cs.WriteTo(&buf)

	// gnark objects (R1CS, ProvingKey, VerifyingKey, Proof) must be instantiated like so:
	newR1CS := groth16.NewCS(ecc.BN254)
	_, _ = newR1CS.ReadFrom(&buf)

	ccsFile, err := os.Create(fmt.Sprintf("%s.txt", "constraint"))
	if err != nil {
	}

	pk_file, err := os.Create(fmt.Sprintf("%s.txt", "pk"))
	if err != nil {
	}

	proof_file, err := os.Create(fmt.Sprintf("%s.txt", "proof"))
	if err != nil {
	}

	vr1cs.WriteTo(ccsFile)

	pk.WriteTo(pk_file)

	proof.WriteRawTo(proof_file)

	_ = ccsFile.Close()
	_ = pk_file.Close()
	_ = vk_file.Close()
	_ = proof_file.Close()
}
