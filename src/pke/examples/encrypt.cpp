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
using namespace std;
const std::string DATAFOLDER = "demoData";

vector<int64_t> readIntsFromFile(string filename) {
  vector<int64_t> vectorOfInts;
  ifstream file(filename);
  if (file.is_open()) {
    string line;
    while (getline(file, line)) {
      vectorOfInts.push_back(stoll(line));
    }
    file.close();
  }
  return vectorOfInts;
}
int main() {
    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
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
    
    // Sample Program: Step 3: Encryption
    
    // Read the integers from the file  // First plaintext vector is encoded
    vector<int64_t> vectorOfInts1 = readIntsFromFile("msg.txt");
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    vector<int64_t> vectorOfInts2 = readIntsFromFile("ka.txt");
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(pk, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(pk, plaintext2);

    std::cout << "The plaintexts have been encrypted." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "msg-bfv.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext msg-bfv has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ka-bfv.txt", ciphertext2, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 2 to ciphertext2.txt" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext ka-bfv has been serialized." << std::endl;

    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

 return 0;
} 
