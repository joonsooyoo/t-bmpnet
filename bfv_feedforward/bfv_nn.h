using namespace std;
using namespace seal;

// bfv_func
vector<Ciphertext> bfv_matrix_mult(vector<Ciphertext> encrypted_input_vector, vector<Ciphertext> encrypted_weight_matrix_Input_to_L1, vector<Ciphertext> encrypted_L1_vector, EncryptionParameters parms, RelinKeys relin_keys, GaloisKeys galois_keys);


void bfv_nn()
{

    float start, end;
    // start time
    start = clock();

    // bfv scheme
	EncryptionParameters parms(scheme_type::bfv);
	// N = poly_modulus_degree ----> Z[X]/X^N + 1
	size_t poly_modulus_degree = 16384;
	// set N
	parms.set_poly_modulus_degree(poly_modulus_degree);
	// set q: ciphertext_modulus
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	
	// batching is a vectorization techqnique to facilitate faster computation by making the vector into a matrix of the form 2 by (N/2)
	// enable batching: find plain_modulus such that it is 20-bit prime number with congruence to 1 modulo 2*poly_modulus_degree
	// PlainModulus::Batching helps finding 20-bit prime number plain_modulus
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    // make context ---> see if the parms are valid
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // context --> qualifiers --> see if batching is enabled
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    // params for Neural Network
    size_t num_input {3};
    size_t num_L1 {4};
    size_t num_L2 {5};
    size_t num_output {2};

    // create keys: secret_key, public_key, relin_keys
    // create classes: encryptor, decryptor, evaluator
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // batching is done by BatchEncoder Class
    BatchEncoder batch_encoder(context);

    // by batching technique, we have 'slots' that are organized in 2 by (N/2) matrix
    // each slot is an integer modulo plain_modulus
    // each slot can be encrypted and computed on
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;
    print_line(__LINE__);
    cout << "Feed Forward Neural Network with [3, 4, 5, 2]" << endl;

    /**************************************************** input to L1 ****************************************************/
    cout << "************ Input to L1 ************" << endl;
    print_line(__LINE__);
    cout << "input vector is encoded/encrypted" << endl;
    // + input vector
    print_line(__LINE__);
    cout << "Input vector: " << endl;
    vector<vector<uint64_t>> input_vector(num_input, vector<uint64_t>(slot_count, 0ULL));
    // [1 0 0; 0 2 0; 0 0 3]
    input_vector.at(0).at(0) = 1; 
    input_vector.at(1).at(1) = 2;
    input_vector.at(2).at(2) = 3;
    // print input
    for (size_t i=0; i<input_vector.size(); i++){
    cout << "input_vector.at " << i << ": "<< endl;
    print_matrix(input_vector.at(i), row_size); 
    }
    // + encoding
    vector<Plaintext> plain_input_vector(num_input);
    for (size_t i=0;i<plain_input_vector.size();i++)
        batch_encoder.encode(input_vector.at(i), plain_input_vector.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_input_vector(num_input);
    for (size_t i=0;i<plain_input_vector.size();i++)
        encryptor.encrypt(plain_input_vector.at(i), encrypted_input_vector.at(i));
    cout << "    + Noise budget in encrypted_input_vector.at(0): " << decryptor.invariant_noise_budget(encrypted_input_vector.at(0)) << " bits" << endl;

    // multiplication by an encrypted weight vector to perform W1 * x
    print_line(__LINE__);
    cout << "Weight vector is encoded/encrypted" << endl;

    print_line(__LINE__);
    cout << "Weight vector: " << endl;
    vector<vector<uint64_t>> weight_matrix_Input_to_L1(num_L1, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<weight_matrix_Input_to_L1.size(); i++){
        for (size_t j=0; j<num_input; j++)
            weight_matrix_Input_to_L1.at(i).at(j) = i+1;
    }
    // print weight_matrix_Input_to_L1
    for (size_t i=0;i<weight_matrix_Input_to_L1.size(); i++){
        cout << "weight_matrix_Input_to_L1.at " << i << " : "<< endl;
        print_matrix(weight_matrix_Input_to_L1.at(i), row_size);
    }

    // + encoding
    vector<Plaintext> plain_weight_matrix_Input_to_L1(num_L1);
    for (size_t i=0;i<plain_weight_matrix_Input_to_L1.size(); i++)
        batch_encoder.encode(weight_matrix_Input_to_L1.at(i), plain_weight_matrix_Input_to_L1.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_weight_matrix_Input_to_L1(num_L1);
    for (size_t i=0;i<encrypted_weight_matrix_Input_to_L1.size(); i++)
        encryptor.encrypt(plain_weight_matrix_Input_to_L1.at(i), encrypted_weight_matrix_Input_to_L1.at(i));

    // + next input_encrypted: encrypted_L1_vector
    vector<Ciphertext> encrypted_L1_vector(num_L1);

    /******** multiplication by a weighted matrix ********/
    // W * x
    encrypted_L1_vector = bfv_matrix_mult(encrypted_input_vector, encrypted_weight_matrix_Input_to_L1, encrypted_L1_vector, parms, relin_keys, galois_keys);
    cout << "    + Noise budget in encrypted_L1_vector.at(i) (after multiplication): " << decryptor.invariant_noise_budget(encrypted_L1_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    vector<Plaintext> plain_tmp(num_L1);
    vector<vector<uint64_t>> pod_tmp(num_L1, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        decryptor.decrypt(encrypted_L1_vector.at(i), plain_tmp.at(i));
    }
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        batch_encoder.decode(plain_tmp.at(i), pod_tmp.at(i));
    }
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        cout << "encrypted_L1_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp.at(i), row_size);
    }

    /******** addition by a bias vector ********/
    print_line(__LINE__);
    cout << "bias vector: " << endl;
    vector<vector<uint64_t>> bias_vector(num_L1, vector<uint64_t>(slot_count, 0ULL));
    // [1 0 0 ... 0; 1 0 0 ... 0; 1 0 0 ... 0; 1 0 0 ... 0]
    for (size_t i=0; i<bias_vector.size(); i++){
        bias_vector.at(i).at(0) = 1;     
    }
    // print input
    for (size_t i=0; i<bias_vector.size(); i++){
        cout << "bias_vector.at " << i << ": "<< endl;
        print_matrix(bias_vector.at(i), row_size); 
    }
    // + encoding
    vector<Plaintext> plain_bias_vector(num_L1);
    for (size_t i=0;i<plain_bias_vector.size();i++)
        batch_encoder.encode(bias_vector.at(i), plain_bias_vector.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_vector(num_L1);
    for (size_t i=0;i<plain_bias_vector.size();i++)
        encryptor.encrypt(plain_bias_vector.at(i), encrypted_bias_vector.at(i));
    // + add
    for (size_t i=0;i<encrypted_bias_vector.size();i++)
        evaluator.add_inplace(encrypted_L1_vector.at(i), encrypted_bias_vector.at(i));
    cout << "    + Noise budget in encrypted_L1_vector.at(i) (after addition): " << decryptor.invariant_noise_budget(encrypted_L1_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        decryptor.decrypt(encrypted_L1_vector.at(i), plain_tmp.at(i));
    }
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        batch_encoder.decode(plain_tmp.at(i), pod_tmp.at(i));
    }
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        cout << "encrypted_L1_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp.at(i), row_size);
    }

    /******** activation function: we use x^2 ********/
    // activation of encrypted_L1_vector: x^2
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        evaluator.square_inplace(encrypted_L1_vector.at(i));
        evaluator.relinearize_inplace(encrypted_L1_vector.at(i), relin_keys);        
    }
    cout << "    + Noise budget in encrypted_L1_vector.at(i) (after activation): " << decryptor.invariant_noise_budget(encrypted_L1_vector.at(0)) << " bits" << endl;
    // decrypt for checking
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        decryptor.decrypt(encrypted_L1_vector.at(i), plain_tmp.at(i));
    }
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        batch_encoder.decode(plain_tmp.at(i), pod_tmp.at(i));
    }
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        cout << "encrypted_L1_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp.at(i), row_size);
    }

    /**************************************************** L1 to L2 ****************************************************/
    cout << "************ L1 to L2 ************" << endl;
    print_line(__LINE__);
    cout << "Weight vector 2: " << endl;
    vector<vector<uint64_t>> weight_matrix_L1_to_L2(num_L2, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<weight_matrix_L1_to_L2.size(); i++){
        for (size_t j=0; j<num_L1; j++)
            weight_matrix_L1_to_L2.at(i).at(j) = i+1;
    }
    // print weight_matrix_L1_to_L2
    for (size_t i=0;i<weight_matrix_L1_to_L2.size(); i++){
        cout << "weight_matrix_L1_to_L2.at " << i << " : "<< endl;
        print_matrix(weight_matrix_L1_to_L2.at(i), row_size);
    }

    // + encoding
    vector<Plaintext> plain_weight_matrix_L1_to_L2(num_L2);
    for (size_t i=0;i<plain_weight_matrix_L1_to_L2.size(); i++)
        batch_encoder.encode(weight_matrix_L1_to_L2.at(i), plain_weight_matrix_L1_to_L2.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_weight_matrix_L1_to_L2(num_L2);
    for (size_t i=0;i<encrypted_weight_matrix_L1_to_L2.size(); i++)
        encryptor.encrypt(plain_weight_matrix_L1_to_L2.at(i), encrypted_weight_matrix_L1_to_L2.at(i));
    // + next input_encrypted: encrypted_L2_vector
    vector<Ciphertext> encrypted_L2_vector(num_L2);

    /******** multiplication by a weighted matrix ********/
    // preprocess
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        evaluator.rotate_rows_inplace(encrypted_L1_vector.at(i), -i, galois_keys);
    }
    // decrypt for checking
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        decryptor.decrypt(encrypted_L1_vector.at(i), plain_tmp.at(i));
    }
    for (size_t i=0; i<encrypted_L1_vector.size(); i++){
        batch_encoder.decode(plain_tmp.at(i), pod_tmp.at(i));
    }
    for (size_t i=0;i<encrypted_L1_vector.size(); i++){
        cout << "encrypted_L1_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp.at(i), row_size);
    }

    // W2 * x
    encrypted_L2_vector = bfv_matrix_mult(encrypted_L1_vector, encrypted_weight_matrix_L1_to_L2, encrypted_L2_vector, parms, relin_keys, galois_keys);
    cout << "    + Noise budget in encrypted_L2_vector.at(i) (after multiplication): " << decryptor.invariant_noise_budget(encrypted_L2_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    vector<Plaintext> plain_tmp_L2(num_L2);
    vector<vector<uint64_t>> pod_tmp_L2(num_L2, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        decryptor.decrypt(encrypted_L2_vector.at(i), plain_tmp_L2.at(i));
    }
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        batch_encoder.decode(plain_tmp_L2.at(i), pod_tmp_L2.at(i));
    }
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        cout << "encrypted_L2_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_L2.at(i), row_size);
    }

    /******** addition by a bias vector ********/
    print_line(__LINE__);
    cout << "bias vector L2: " << endl;
    vector<vector<uint64_t>> bias_vector_L2(num_L2, vector<uint64_t>(slot_count, 0ULL));
    // [1 0 0 ... 0; 1 0 0 ... 0; 1 0 0 ... 0; 1 0 0 ... 0]
    for (size_t i=0; i<bias_vector_L2.size(); i++){
        bias_vector_L2.at(i).at(0) = 1;     
    }
    // print input
    for (size_t i=0; i<bias_vector_L2.size(); i++){
        cout << "bias_vector_L2.at " << i << ": "<< endl;
        print_matrix(bias_vector_L2.at(i), row_size); 
    }
    // + encoding
    vector<Plaintext> plain_bias_vector_L2(num_L2);
    for (size_t i=0;i<plain_bias_vector_L2.size();i++)
        batch_encoder.encode(bias_vector_L2.at(i), plain_bias_vector_L2.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_vector_L2(num_L2);
    for (size_t i=0;i<encrypted_bias_vector_L2.size();i++)
        encryptor.encrypt(plain_bias_vector_L2.at(i), encrypted_bias_vector_L2.at(i));
    // + add
    for (size_t i=0;i<encrypted_L2_vector.size();i++)
        evaluator.add_inplace(encrypted_L2_vector.at(i), encrypted_bias_vector_L2.at(i));
    cout << "    + Noise budget in encrypted_L2_vector.at(i) (after addition): " << decryptor.invariant_noise_budget(encrypted_L2_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        decryptor.decrypt(encrypted_L2_vector.at(i), plain_tmp_L2.at(i));
    }
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        batch_encoder.decode(plain_tmp_L2.at(i), pod_tmp_L2.at(i));
    }
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        cout << "encrypted_L2_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_L2.at(i), row_size);
    }

    /******** activation function: we use x^2 ********/
    // activation of encrypted_L2_vector: x^2
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        evaluator.square_inplace(encrypted_L2_vector.at(i));
        evaluator.relinearize_inplace(encrypted_L2_vector.at(i), relin_keys);        
    }
    cout << "    + Noise budget in encrypted_L2_vector.at(i) (after activation): " << decryptor.invariant_noise_budget(encrypted_L2_vector.at(0)) << " bits" << endl;
    // decrypt for checking
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        decryptor.decrypt(encrypted_L2_vector.at(i), plain_tmp_L2.at(i));
    }
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        batch_encoder.decode(plain_tmp_L2.at(i), pod_tmp_L2.at(i));
    }
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        cout << "encrypted_L2_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_L2.at(i), row_size);
    }

    /**************************************************** L2 to Output ****************************************************/
    cout << "************ L2 to Output ************" << endl;
    print_line(__LINE__);
    cout << "Weight vector 3: " << endl;
    vector<vector<uint64_t>> weight_matrix_L2_to_Output(num_output, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<weight_matrix_L2_to_Output.size(); i++){
        for (size_t j=0; j<num_L2; j++)
            weight_matrix_L2_to_Output.at(i).at(j) = i+1;
    }
    // print weight_matrix_L2_to_Output
    for (size_t i=0;i<weight_matrix_L2_to_Output.size(); i++){
        cout << "weight_matrix_L2_to_Output.at " << i << " : "<< endl;
        print_matrix(weight_matrix_L2_to_Output.at(i), row_size);
    }

    // + encoding
    vector<Plaintext> plain_weight_matrix_L2_to_Output(num_output);
    for (size_t i=0;i<plain_weight_matrix_L2_to_Output.size(); i++)
        batch_encoder.encode(weight_matrix_L2_to_Output.at(i), plain_weight_matrix_L2_to_Output.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_weight_matrix_L2_to_Output(num_output);
    for (size_t i=0;i<encrypted_weight_matrix_L2_to_Output.size(); i++)
        encryptor.encrypt(plain_weight_matrix_L2_to_Output.at(i), encrypted_weight_matrix_L2_to_Output.at(i));
    // + next input_encrypted: encrypted_Output_vector
    vector<Ciphertext> encrypted_Output_vector(num_output);

    /******** multiplication by a weighted matrix ********/
    // preprocess
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        evaluator.rotate_rows_inplace(encrypted_L2_vector.at(i), -i, galois_keys);
    }
    // decrypt for checking
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        decryptor.decrypt(encrypted_L2_vector.at(i), plain_tmp_L2.at(i));
    }
    for (size_t i=0; i<encrypted_L2_vector.size(); i++){
        batch_encoder.decode(plain_tmp_L2.at(i), pod_tmp_L2.at(i));
    }
    for (size_t i=0;i<encrypted_L2_vector.size(); i++){
        cout << "encrypted_L2_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_L2.at(i), row_size);
    }

    // W3 * x
    encrypted_Output_vector = bfv_matrix_mult(encrypted_L2_vector, encrypted_weight_matrix_L2_to_Output, encrypted_Output_vector, parms, relin_keys, galois_keys);
    cout << "    + Noise budget in encrypted_Output_vector.at(i) (after multiplication): " << decryptor.invariant_noise_budget(encrypted_Output_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    vector<Plaintext> plain_tmp_Output(num_output);
    vector<vector<uint64_t>> pod_tmp_Output(num_output, vector<uint64_t>(slot_count, 0ULL));

    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        decryptor.decrypt(encrypted_Output_vector.at(i), plain_tmp_Output.at(i));
    }
    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        batch_encoder.decode(plain_tmp_Output.at(i), pod_tmp_Output.at(i));
    }
    for (size_t i=0;i<encrypted_Output_vector.size(); i++){
        cout << "encrypted_Output_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_Output.at(i), row_size);
    }

    /******** addition by a bias vector ********/
    print_line(__LINE__);
    cout << "bias vector Output: " << endl;
    vector<vector<uint64_t>> bias_vector_Output(num_output, vector<uint64_t>(slot_count, 0ULL));
    // [1 0 0 ... 0; 1 0 0 ... 0]
    for (size_t i=0; i<bias_vector_Output.size(); i++){
        bias_vector_Output.at(i).at(0) = 1;     
    }
    // print input
    for (size_t i=0; i<bias_vector_Output.size(); i++){
        cout << "bias_vector_Output.at " << i << ": "<< endl;
        print_matrix(bias_vector_Output.at(i), row_size); 
    }
    // + encoding
    vector<Plaintext> plain_bias_vector_Output(num_output);
    for (size_t i=0;i<plain_bias_vector_Output.size();i++)
        batch_encoder.encode(bias_vector_Output.at(i), plain_bias_vector_Output.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_vector_Output(num_output);
    for (size_t i=0;i<encrypted_bias_vector_Output.size();i++)
        encryptor.encrypt(plain_bias_vector_Output.at(i), encrypted_bias_vector_Output.at(i));
    // + add
    for (size_t i=0;i<encrypted_Output_vector.size();i++)
        evaluator.add_inplace(encrypted_Output_vector.at(i), encrypted_bias_vector_Output.at(i));
    cout << "    + Noise budget in encrypted_Output_vector.at(i) (after addition): " << decryptor.invariant_noise_budget(encrypted_Output_vector.at(0)) << " bits" << endl;

    // decrypt for checking
    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        decryptor.decrypt(encrypted_Output_vector.at(i), plain_tmp_Output.at(i));
    }
    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        batch_encoder.decode(plain_tmp_Output.at(i), pod_tmp_Output.at(i));
    }
    for (size_t i=0;i<encrypted_Output_vector.size(); i++){
        cout << "encrypted_Output_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_Output.at(i), row_size);
    }

    /******** activation function: we use x^2 ********/
    // activation of encrypted_Output_vector: x^2
    for (size_t i=0;i<encrypted_Output_vector.size(); i++){
        evaluator.square_inplace(encrypted_Output_vector.at(i));
        evaluator.relinearize_inplace(encrypted_Output_vector.at(i), relin_keys);        
    }
    cout << "    + Noise budget in encrypted_Output_vector.at(i) (after activation): " << decryptor.invariant_noise_budget(encrypted_Output_vector.at(0)) << " bits" << endl;
    // decrypt for checking
    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        decryptor.decrypt(encrypted_Output_vector.at(i), plain_tmp_Output.at(i));
    }
    for (size_t i=0; i<encrypted_Output_vector.size(); i++){
        batch_encoder.decode(plain_tmp_Output.at(i), pod_tmp_Output.at(i));
    }
    for (size_t i=0;i<encrypted_Output_vector.size(); i++){
        cout << "encrypted_Output_vector.at " << i << " : "<< endl;
        print_matrix(pod_tmp_Output.at(i), row_size);
    }

    // end time
    end = clock();
    printf("**Total Estimated Time : %f (seconds)\n", double((end - start)/CLOCKS_PER_SEC));


}

vector<Ciphertext> bfv_matrix_mult(vector<Ciphertext> encrypted_input_vector, vector<Ciphertext> encrypted_weight_matrix_Input_to_L1, vector<Ciphertext> encrypted_L1_vector, EncryptionParameters parms, RelinKeys relin_keys, GaloisKeys galois_keys){

    SEALContext context(parms);
    Evaluator evaluator(context);
    // tmp ciphertext
    Ciphertext tmp;

    for (size_t i=0; i<encrypted_weight_matrix_Input_to_L1.size(); i++){

        for (size_t j=0; j<encrypted_input_vector.size(); j++){

            if (j == 0) {
                evaluator.multiply(encrypted_weight_matrix_Input_to_L1.at(i), encrypted_input_vector.at(j), encrypted_L1_vector.at(i));
                evaluator.relinearize_inplace(encrypted_L1_vector.at(i), relin_keys);

            } else {
                evaluator.multiply(encrypted_weight_matrix_Input_to_L1.at(i), encrypted_input_vector.at(j), tmp);
                evaluator.relinearize_inplace(tmp, relin_keys);    
                evaluator.rotate_rows_inplace(tmp, j, galois_keys);
                evaluator.add_inplace(encrypted_L1_vector.at(i), tmp);
            }
        }
    }

    return encrypted_L1_vector;

}