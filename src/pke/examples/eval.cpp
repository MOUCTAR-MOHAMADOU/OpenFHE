/*
  Simple example for BFVrns (integer arithmetic) with serialization. Refer to the simple-real-numbers-serial file for
  an example of how to use. this in a "client-server" setup
 */
#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
const std::string DATAFOLDER = "demoData";

int main() {
    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return 1;
    }
    std::cout << "The public key has been deserialized." << std::endl;

    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;

    std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
    if (!erkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval rotation keys." << std::endl;

    Ciphertext<DCRTPoly> ct1;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/msg-bfv.txt", ct1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext msg-bfv has been deserialized." << std::endl;

    Ciphertext<DCRTPoly> ct2;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ka-bfv.txt", ct2, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext has been deserialized." << std::endl;

    // Sample Program: Step 4: Evaluation
    
    // Homomorphic additions
    auto ciphertextAdd12     = cc->EvalAdd(ct1, ct2);              // iphertext2);
    // Homomorphic multiplications
    auto ciphertextMul12      = cc->EvalMult(ct1, ct2);              // iphertext2);
    // Homomorphic rotations
    auto ciphertextRot1 = cc->EvalRotate(ct2, 2);
    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertextAdd12.txt", ciphertextAdd12, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertextAdd12.txt" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext msg-bfv has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertextMul12.txt", ciphertextMul12, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 2 to ciphertextMul12.txt" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ka-bfv has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertextRot1.txt", ciphertextRot1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 2 to ciphertextRot1.txt" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ka-bfv has been serialized." << std::endl;

    return 0;
}