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
    std::cout << "The second ciphertext ka-bfv has been deserialized." << std::endl;

    // Sample Program: Step 5: Decryption
    PrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    // Decrypt the ciphertext
    Plaintext msg_decrypted;
    cc->Decrypt(sk, ct1, &msg_decrypted);
    // Output the decrypted plaintext
    std::cout << "Decrypted plaintext #msg: " << msg_decrypted << std::endl;

    // Decrypt the ciphertext
    Plaintext ka_decrypted;
    cc->Decrypt(sk, ct2, &ka_decrypted);
    // Output the decrypted plaintext
    std::cout << "Decrypted plaintext #ka: " << ka_decrypted << std::endl;
////////////////////////////////////
    Ciphertext<DCRTPoly> ciphertextAdd12;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertextAdd12.txt", ciphertextAdd12, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ciphertextAdd12 has been deserialized." << std::endl;
    Ciphertext<DCRTPoly> ciphertextMul12;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertextMul12.txt", ciphertextMul12, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ciphertextMul12 has been deserialized." << std::endl;
    Ciphertext<DCRTPoly> ciphertextRot1;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertextRot1.txt", ciphertextRot1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ciphertextRot1 has been deserialized." << std::endl;


    // Decrypt the result of additions
    Plaintext plaintextAddResult;
    cc->Decrypt(sk, ciphertextAdd12, &plaintextAddResult);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cc->Decrypt(sk, ciphertextMul12, &plaintextMultResult);

    // Decrypt the result of rotations
    Plaintext plaintextRot1;
    cc->Decrypt(sk, ciphertextRot1, &plaintextRot1);

    // Shows only the same number of elements as in the original plaintext vector
    // By default it will show all coefficients in the BFV-encoded polynomial
    plaintextRot1->SetLength(16);

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2: " << plaintextAddResult << std::endl;
    std::cout << "#1 * #2: " << plaintextMultResult << std::endl;
    std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
       
    return 0;
}
