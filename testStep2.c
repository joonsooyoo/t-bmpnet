#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <HomOper.c>


int main() { 
    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //read the 2x16 ciphertexts
    int length = 8;
    int res_length = 8;
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(length, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(length, params);

    //reads the 2x16 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<length; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<length; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    //do some operations on the ciphertexts: here, we will compute the
    
    LweSample* result = new_gate_bootstrapping_ciphertext_array(res_length, params);
    LweSample* result2 = new_gate_bootstrapping_ciphertext_array(res_length, params); // HomDiv

    float time = -clock();

    ////// start operation ///////

    HomMLPNN(result, ciphertext1, ciphertext2, length, bk);  

    ////// end operation ///////

    time += clock();
    time = time/(CLOCKS_PER_SEC);
    printf("done in %f seconds...\n", time);

    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<res_length; i++) 
	    export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    
    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(res_length, result);
    delete_gate_bootstrapping_ciphertext_array(res_length, result2); // HomDiv
    delete_gate_bootstrapping_ciphertext_array(length, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(length, ciphertext1);
    delete_gate_bootstrapping_cloud_keyset(bk);


}


