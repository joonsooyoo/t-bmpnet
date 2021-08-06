#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>


int main() {

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 8 ciphertexts of the result
    int length = 8;
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(length, params);

    //import the 8-bit ciphertexts from the answer file
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<length; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    fclose(answer_data);

    //decrypt and rebuild the 32-bit plaintext answer
    int32_t int_answer = 0;
    for (int i=0; i<length; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }

    printf("And the result is: %d\n",int_answer);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(length, answer);
    delete_gate_bootstrapping_secret_keyset(key);
}

