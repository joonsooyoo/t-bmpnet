using namespace std;
using namespace seal;

/*
function:
    
    (1) matrix mult
    (2) sigmoid by ckks method
*/

vector<Ciphertext> ckks_matrix_mult(vector<Ciphertext> encrypted_init_vector, vector<Ciphertext> encrypted_weight_matrix, vector<Ciphertext> encrypted_result_vector, EncryptionParameters parms, RelinKeys relin_keys, GaloisKeys gal_keys);
vector<Ciphertext> ckks_sigmoid(vector<Ciphertext> encrypted_L_init_vector, size_t num_L_init, double scale, EncryptionParameters parms, RelinKeys relin_keys);
vector<Ciphertext> ckks_preprocess(vector<Ciphertext> encrypted_L_init_vector, double scale, EncryptionParameters parms, GaloisKeys gal_keys);

void ckks_nn_sigmoid(){

    float start, end;
	// start time
	start = clock();

	print_example_banner("ckks ckks_experiment5: feedforward NN with layers [3, 4, 5, 2] using sigmoid as an activation function");
    // params for Neural Network
    size_t num_input {3};
    size_t num_L1 {4};
    size_t num_L2 {5};
    size_t num_output {2};

	// parms: poly_modulus_degree, coeff_modulus
	EncryptionParameters parms(scheme_type::ckks);	
	// poly_modulus_degree can be of the following: 1024(10), 2048(11), 4096(12), 8192(13), 16384(14), 32768(15)
	// show possible poly_modulus_degree 
	print_line(__LINE__);
	cout << "poly_modulus_degree lists: " << "1024(10), 2048(11), 4096(12), 8192(13), 16384(14), 32768(15)" << endl;
	size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40 }));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40 }));
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}));    
    // max: 881
    // 840
    print_line(__LINE__);
    cout << "Maximum bits for poly_modulus_degree of " << poly_modulus_degree << " is " << CoeffModulus::MaxBitCount(poly_modulus_degree) 
    	 << " bits" << endl;

    // scale
	double scale = pow(2.0, 40);
    // double scale = pow(2.0, 30);    
	// context
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // keys(sk, pk, rk, gk) and cryptors
	KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // encoder(context);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // input and number of neurons per layer [3, 4, 5, 2]
    print_line(__LINE__);
    cout << "input vector is encoded/encrypted" << endl;
	// + input vector
	print_line(__LINE__);
	cout << "Input vector: " << endl;
	vector<vector<double>> input_vector(num_input, vector<double>(num_input));
	// [1 0 0; 0 2 0; 0 0 3]
    input_vector.at(0).at(0) = 0.1; 
	input_vector.at(1).at(1) = 0.2;
	input_vector.at(2).at(2) = 0.3;
	print_matrix(input_vector);	

    // + encoding
    vector<Plaintext> plain_input_vector(num_input);
    for (size_t i=0;i<plain_input_vector.size();i++)
        encoder.encode(input_vector.at(i), scale, plain_input_vector.at(i));
 
    // + encrypt
    vector<Ciphertext> encrypted_input_vector(num_input);
    for (size_t i=0;i<plain_input_vector.size();i++)
        encryptor.encrypt(plain_input_vector.at(i), encrypted_input_vector.at(i));

    // multiplication by an encrypted weight vector to perform W1 * x
    print_line(__LINE__);
    cout << "Weight vector is encoded/encrypted" << endl;
	// + input vector
	print_line(__LINE__);
	cout << "Weight vector: " << endl;
	vector<vector<double>> weight_matrix(num_L1, vector<double>(num_input));
	for (size_t i=0; i<weight_matrix.size(); i++){
    	for (size_t j=0; j<weight_matrix[0].size(); j++)
    		weight_matrix.at(i).at(j) = i+1;
    }
    print_matrix(weight_matrix);
	// + encoding
	vector<Plaintext> plain_weight_matrix(num_L1);
	for (size_t i=0;i<plain_weight_matrix.size(); i++)
		encoder.encode(weight_matrix.at(i), scale, plain_weight_matrix.at(i));
	// + encrypt
	vector<Ciphertext> encrypted_weight_matrix(num_L1);
	for (size_t i=0;i<encrypted_weight_matrix.size(); i++)
		encryptor.encrypt(plain_weight_matrix.at(i), encrypted_weight_matrix.at(i));

     // + check scale and modulus chain
    print_line(__LINE__);
    cout << "    + scale of encrypted_input: " << log2(encrypted_weight_matrix.at(0).scale()) << " bits" << endl;
    cout << "    + modulus chain index for encrypted_input: " << context.get_context_data(encrypted_weight_matrix.at(0).parms_id())->chain_index() 
    	 << " floor" << endl;
	// + next input_encrypted: encrypted_L1_vector
    vector<Ciphertext> encrypted_L1_vector(num_L1);

     // + evaluation of weight_matrix * L1_vector
    encrypted_L1_vector = ckks_matrix_mult(encrypted_input_vector, encrypted_weight_matrix, encrypted_L1_vector, parms, relin_keys, gal_keys);
    cout << "    + modulus chain index for encrypted_L1_vector.at(0): " << context.get_context_data(encrypted_L1_vector.at(0).parms_id())->chain_index() 
     << " floor" << endl;

    // decrypt to check whether it 
    print_line(__LINE__);
    cout << "Decrypt to check L1_1 ... [6, 12, 18, 24, 0, ..., 0] ?" << endl;
    // + decrypt
    vector<Plaintext> plain_L1_vector(num_L1);
    for (size_t i=0; i<encrypted_L1_vector.size(); i++)
	   decryptor.decrypt(encrypted_L1_vector.at(i), plain_L1_vector.at(i));
    // + decode
    vector<vector<double>> result_vector(num_L1, vector<double>(slot_count));
    for (size_t i=0; i<plain_L1_vector.size(); i++)
        encoder.decode(plain_L1_vector.at(i), result_vector.at(i));
    for (size_t i=0; i<plain_L1_vector.size(); i++){
        cout << "L1_" << i+1 << ": " << endl;
        print_vector(result_vector.at(i));
    }

    /***** addition by (encrypted) bias *****/
    print_line(__LINE__);
    cout << "bias at L1 is encoded/encrypted" << endl;
    vector<vector<double>> bias_L1_vector(num_L1, vector<double>(1));
    bias_L1_vector.at(0).at(0) = 0.1;
    bias_L1_vector.at(1).at(0) = 0.1;
    bias_L1_vector.at(2).at(0) = 0.1;
    bias_L1_vector.at(3).at(0) = 0.1;
    // + encode
    vector<Plaintext> plain_bias_L1_vector(num_L1);
    for (size_t i=0; i<num_L1; i++)
        encoder.encode(bias_L1_vector.at(i), scale, plain_bias_L1_vector.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_L1_vector(num_L1);
    for (size_t i=0; i<num_L1; i++)
        encryptor.encrypt(plain_bias_L1_vector.at(i), encrypted_bias_L1_vector.at(i));
    // + add
    for (size_t i=0; i<num_L1; i++){
        evaluator.mod_switch_to_inplace(encrypted_bias_L1_vector.at(i), encrypted_L1_vector.at(i).parms_id());
        encrypted_L1_vector.at(i).scale() = scale;
        evaluator.add_inplace(encrypted_L1_vector.at(i), encrypted_bias_L1_vector.at(i));
    }

    // decrypt to check whether it 
    print_line(__LINE__);
    cout << "Decrypt to check result (after bias)?" << endl;
    // + decrypt
    for (size_t i=0; i<encrypted_L1_vector.size(); i++)
       decryptor.decrypt(encrypted_L1_vector.at(i), plain_L1_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_L1_vector.size(); i++)
        encoder.decode(plain_L1_vector.at(i), result_vector.at(i));
    for (size_t i=0; i<plain_L1_vector.size(); i++){
        cout << "L1_" << i+1 << ": " << endl;
        print_vector(result_vector.at(i));
    }

    /***** ckks_sigmoid *****/
    encrypted_L1_vector = ckks_sigmoid(encrypted_L1_vector, num_L1, scale, parms, relin_keys);
    
    // + decrypt
    for (size_t i=0; i<encrypted_L1_vector.size(); i++)
       decryptor.decrypt(encrypted_L1_vector.at(i), plain_L1_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_L1_vector.size(); i++)
        encoder.decode(plain_L1_vector.at(i), result_vector.at(i));
    for (size_t i=0; i<plain_L1_vector.size(); i++){
        cout << "L1_" << i+1 << ": " << endl;
        print_vector(result_vector.at(i));
    }

    /********************
        
        L1 to L2

    ********************/
    /***** multiplication by an encrypted weight vector to perform W2 * encrypted_L1_vector *****/
    // preprocess
    encrypted_L1_vector = ckks_preprocess(encrypted_L1_vector, scale, parms, gal_keys);

    print_line(__LINE__);
    cout << "Weight vector 2 is encoded/encrypted" << endl;
    print_line(__LINE__);
    cout << "Weight vector 2: " << endl;
    vector<vector<double>> weight_matrix_L1_to_L2(num_L2, vector<double>(num_L1));
    for (size_t i=0; i<weight_matrix_L1_to_L2.size(); i++){
        for (size_t j=0; j<weight_matrix_L1_to_L2[0].size(); j++)
            weight_matrix_L1_to_L2.at(i).at(j) = i+1;
    }
    print_matrix(weight_matrix_L1_to_L2);
    // + encoding
    vector<Plaintext> plain_weight_matrix_L1_to_L2(num_L2);
    for (size_t i=0;i<plain_weight_matrix_L1_to_L2.size(); i++)
        encoder.encode(weight_matrix_L1_to_L2.at(i), scale, plain_weight_matrix_L1_to_L2.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_weight_matrix_L1_to_L2(num_L2);
    for (size_t i=0;i<encrypted_weight_matrix_L1_to_L2.size(); i++)
        encryptor.encrypt(plain_weight_matrix_L1_to_L2.at(i), encrypted_weight_matrix_L1_to_L2.at(i));

     // + check scale and modulus chain
    print_line(__LINE__);
    cout << "    + scale of encrypted_input: " << log2(encrypted_weight_matrix_L1_to_L2.at(0).scale()) << " bits" << endl;
    cout << "    + modulus chain index for encrypted_input: " << context.get_context_data(encrypted_weight_matrix_L1_to_L2.at(0).parms_id())->chain_index() 
         << " floor" << endl;

    // + next input_encrypted: encrypted_L2_vector
    vector<Ciphertext> encrypted_L2_vector(num_L2);
     
    /***** evaluation of weight_matrix_L1_to_L2 * L1_vector *****/
    encrypted_L2_vector = ckks_matrix_mult(encrypted_L1_vector, encrypted_weight_matrix_L1_to_L2, encrypted_L2_vector, parms, relin_keys, gal_keys);
    cout << "    + modulus chain index for encrypted_L2_vector.at(0): " << context.get_context_data(encrypted_L2_vector.at(0).parms_id())->chain_index() 
     << " floor" << endl;

    /***** addition by (encrypted) bias *****/
    print_line(__LINE__);
    cout << "bias at L2 is encoded/encrypted" << endl;
    vector<vector<double>> bias_L2_vector(num_L2, vector<double>(1));
    bias_L2_vector.at(0).at(0) = 0.1;
    bias_L2_vector.at(1).at(0) = 0.1;
    bias_L2_vector.at(2).at(0) = 0.1;
    bias_L2_vector.at(3).at(0) = 0.1;
    bias_L2_vector.at(4).at(0) = 0.1;
    // + encode
    vector<Plaintext> plain_bias_L2_vector(num_L2);
    for (size_t i=0; i<num_L2; i++)
        encoder.encode(bias_L2_vector.at(i), scale, plain_bias_L2_vector.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_L2_vector(num_L2);
    for (size_t i=0; i<num_L2; i++)
        encryptor.encrypt(plain_bias_L2_vector.at(i), encrypted_bias_L2_vector.at(i));
    // + add
    for (size_t i=0; i<num_L2; i++){
        evaluator.mod_switch_to_inplace(encrypted_bias_L2_vector.at(i), encrypted_L2_vector.at(i).parms_id());
        encrypted_L2_vector.at(i).scale() = scale;
        evaluator.add_inplace(encrypted_L2_vector.at(i), encrypted_bias_L2_vector.at(i));
    }

    // decrypt to check (addition by bias)
    print_line(__LINE__);
    cout << "Decrypt to check result (after bias)?" << endl;
    // + decrypt
    vector<Plaintext> plain_L2_vector(num_L2);
    for (size_t i=0; i<encrypted_L2_vector.size(); i++)
       decryptor.decrypt(encrypted_L2_vector.at(i), plain_L2_vector.at(i));
    // + decode
    vector<vector<double>> result_vector_2(num_L2, vector<double>(slot_count));
    for (size_t i=0; i<plain_L2_vector.size(); i++)
        encoder.decode(plain_L2_vector.at(i), result_vector_2.at(i));
    for (size_t i=0; i<plain_L2_vector.size(); i++){
        cout << "L2_" << i+1 << ": " << endl;
        print_vector(result_vector_2.at(i));
    }
    /***** ckks_sigmoid *****/
    encrypted_L2_vector = ckks_sigmoid(encrypted_L2_vector, num_L2, scale, parms, relin_keys);

    // + decrypt
    for (size_t i=0; i<encrypted_L2_vector.size(); i++)
       decryptor.decrypt(encrypted_L2_vector.at(i), plain_L2_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_L2_vector.size(); i++)
        encoder.decode(plain_L2_vector.at(i), result_vector_2.at(i));
    for (size_t i=0; i<plain_L2_vector.size(); i++){
        cout << "L2_" << i+1 << ": " << endl;
        print_vector(result_vector_2.at(i));
    }
    /********************
        
        L2 to Output

    ********************/
    /***** multiplication by an encrypted weight vector to perform W2 * encrypted_L1_vector *****/
    // preprocess
    encrypted_L2_vector = ckks_preprocess(encrypted_L2_vector, scale, parms, gal_keys);

    print_line(__LINE__);
    cout << "Weight vector 3 is encoded/encrypted" << endl;
    print_line(__LINE__);
    cout << "Weight vector 3: " << endl;
    vector<vector<double>> weight_matrix_L2_to_Output(num_output, vector<double>(num_L2));
    for (size_t i=0; i<weight_matrix_L2_to_Output.size(); i++){
        for (size_t j=0; j<weight_matrix_L2_to_Output[0].size(); j++)
            weight_matrix_L2_to_Output.at(i).at(j) = i+1;
    }
    print_matrix(weight_matrix_L2_to_Output);
    // + encoding
    vector<Plaintext> plain_weight_matrix_L2_to_Output(num_output);
    for (size_t i=0;i<plain_weight_matrix_L2_to_Output.size(); i++)
        encoder.encode(weight_matrix_L2_to_Output.at(i), scale, plain_weight_matrix_L2_to_Output.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_weight_matrix_L2_to_Output(num_output);
    for (size_t i=0;i<encrypted_weight_matrix_L2_to_Output.size(); i++)
        encryptor.encrypt(plain_weight_matrix_L2_to_Output.at(i), encrypted_weight_matrix_L2_to_Output.at(i));

     // + check scale and modulus chain
    print_line(__LINE__);
    cout << "    + scale of encrypted_input: " << log2(encrypted_weight_matrix_L2_to_Output.at(0).scale()) << " bits" << endl;
    cout << "    + modulus chain index for encrypted_input: " << context.get_context_data(encrypted_weight_matrix_L2_to_Output.at(0).parms_id())->chain_index() 
         << " floor" << endl;

    // + next input_encrypted: encrypted_L2_vector
    vector<Ciphertext> encrypted_Output_vector(num_output);
     
    /***** evaluation of weight_matrix_L1_to_L2 * L1_vector *****/
    encrypted_Output_vector = ckks_matrix_mult(encrypted_L2_vector, encrypted_weight_matrix_L2_to_Output, encrypted_Output_vector, parms, relin_keys, gal_keys);
    cout << "    + modulus chain index for encrypted_Output_vector.at(0): " << context.get_context_data(encrypted_Output_vector.at(0).parms_id())->chain_index() 
     << " floor" << endl;

    /***** addition by (encrypted) bias *****/
    print_line(__LINE__);
    cout << "bias at Output is encoded/encrypted" << endl;
    vector<vector<double>> bias_Output_vector(num_output, vector<double>(1));
    bias_Output_vector.at(0).at(0) = 0.1;
    bias_Output_vector.at(1).at(0) = 0.1;
    // + encode
    vector<Plaintext> plain_bias_Output_vector(num_output);
    for (size_t i=0; i<num_output; i++)
        encoder.encode(bias_Output_vector.at(i), scale, plain_bias_Output_vector.at(i));
    // + encrypt
    vector<Ciphertext> encrypted_bias_Output_vector(num_output);
    for (size_t i=0; i<num_output; i++)
        encryptor.encrypt(plain_bias_Output_vector.at(i), encrypted_bias_Output_vector.at(i));
    // + add
    for (size_t i=0; i<num_output; i++){
        evaluator.mod_switch_to_inplace(encrypted_bias_Output_vector.at(i), encrypted_Output_vector.at(i).parms_id());
        encrypted_Output_vector.at(i).scale() = scale;
        evaluator.add_inplace(encrypted_Output_vector.at(i), encrypted_bias_Output_vector.at(i));
    }

    // decrypt to check (addition by bias)
    print_line(__LINE__);
    cout << "Decrypt to check result (after bias)?" << endl;
    // + decrypt
    vector<Plaintext> plain_Output_vector(num_output);
    for (size_t i=0; i<encrypted_Output_vector.size(); i++)
       decryptor.decrypt(encrypted_Output_vector.at(i), plain_Output_vector.at(i));
    // + decode
    vector<vector<double>> result_vector_3(num_output, vector<double>(slot_count));
    for (size_t i=0; i<plain_Output_vector.size(); i++)
        encoder.decode(plain_Output_vector.at(i), result_vector_3.at(i));
    for (size_t i=0; i<plain_Output_vector.size(); i++){
        cout << "L3_" << i+1 << ": " << endl;
        print_vector(result_vector_3.at(i));
    }
    /***** ckks_sigmoid *****/
    encrypted_Output_vector = ckks_sigmoid(encrypted_Output_vector, num_output, scale, parms, relin_keys);

    // + decrypt
    for (size_t i=0; i<encrypted_Output_vector.size(); i++)
       decryptor.decrypt(encrypted_Output_vector.at(i), plain_Output_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_Output_vector.size(); i++)
        encoder.decode(plain_Output_vector.at(i), result_vector_3.at(i));
    for (size_t i=0; i<plain_Output_vector.size(); i++){
        cout << "L3_" << i+1 << ": " << endl;
        print_vector(result_vector_3.at(i));
    }

    // end time
    end = clock();
    printf("**Total Estimated Time : %f (seconds)\n", double((end - start)/CLOCKS_PER_SEC));

}


vector<Ciphertext> ckks_matrix_mult(vector<Ciphertext> encrypted_init_vector, vector<Ciphertext> encrypted_weight_matrix, vector<Ciphertext> encrypted_result_vector, EncryptionParameters parms, RelinKeys relin_keys, GaloisKeys gal_keys){
    
    /*
    matrix multiplication

    */
    SEALContext context(parms);
    Evaluator evaluator(context);


    print_line(__LINE__);
    cout << "Evaluation from input_vector to L1" << endl;

    Ciphertext tmp;

    if (encrypted_init_vector.at(0).parms_id() == encrypted_weight_matrix.at(0).parms_id()){
        // this is input to L1
        for (size_t i=0; i<encrypted_weight_matrix.size(); i++){
         
            for (size_t j=0; j<encrypted_init_vector.size(); j++){

                if (j==0) {
                    // x11 * w1
                    evaluator.multiply(encrypted_init_vector.at(j), encrypted_weight_matrix.at(i), encrypted_result_vector.at(i)); // [1 0 0 0 0 ...] * [1 1 1 0 0 0 0 ...]
                    evaluator.relinearize_inplace(encrypted_result_vector.at(i), relin_keys);
                    evaluator.rescale_to_next_inplace(encrypted_result_vector.at(i));
                }
                else {
                    // x22 * w1
                    evaluator.multiply(encrypted_init_vector.at(j), encrypted_weight_matrix.at(i), tmp); // [0 2 0 0 0 ...] * [1 1 1 0 0 0 0 ...]
                    evaluator.relinearize_inplace(tmp, relin_keys);
                    evaluator.rescale_to_next_inplace(tmp);    
                    evaluator.rotate_vector_inplace(tmp, j, gal_keys); // [2 0 0 0 0 ...]
                    evaluator.add_inplace(encrypted_result_vector.at(i), tmp); // [1+2 0 0 0 0 ...]                
                }
            }
        }
    } else {
        // this is other than input to L1 (e.g., L1 to L2)
        for (size_t i=0; i<encrypted_weight_matrix.size(); i++){
         
            for (size_t j=0; j<encrypted_init_vector.size(); j++){
                // this is the only difference (make their floor to be equal)
                evaluator.mod_switch_to_inplace(encrypted_weight_matrix.at(i), encrypted_init_vector.at(j).parms_id());
                
                if (j==0) {
                    // x11 * w1
                    evaluator.multiply(encrypted_init_vector.at(j), encrypted_weight_matrix.at(i), encrypted_result_vector.at(i)); // [1 0 0 0 0 ...] * [1 1 1 0 0 0 0 ...]
                    evaluator.relinearize_inplace(encrypted_result_vector.at(i), relin_keys);
                    evaluator.rescale_to_next_inplace(encrypted_result_vector.at(i));
                }
                else {
                    // x22 * w1
                    evaluator.multiply(encrypted_init_vector.at(j), encrypted_weight_matrix.at(i), tmp); // [0 2 0 0 0 ...] * [1 1 1 0 0 0 0 ...]
                    evaluator.relinearize_inplace(tmp, relin_keys);
                    evaluator.rescale_to_next_inplace(tmp);    
                    evaluator.rotate_vector_inplace(tmp, j, gal_keys); // [2 0 0 0 0 ...]
                    evaluator.add_inplace(encrypted_result_vector.at(i), tmp); // [1+2 0 0 0 0 ...]                
                }
            }
        }

    }

    return encrypted_result_vector;
}

vector<Ciphertext> ckks_sigmoid(vector<Ciphertext> encrypted_L_init_vector, size_t num_L_init, double scale, EncryptionParameters parms, RelinKeys relin_keys){
    /* 
    parameter information: 
        
        (1) encrypted_L_init_vector: input layer L_init 
        (2) encrypted_L_next_vector: next layer L_next
        (3) num_L_init: number of neurons at layer L_init
  
    */

    // sigmoid function for ckks: b0 + b1*x + b3*x^3 + b5*x^5 + b7*x^7
    // where b0 = 0.5, b1 = 0.2169, b3 = -0.0082, b5 = 0.00016583, b7 = -0.0000011956 
    SEALContext context(parms);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);


    double b0 = 0.5, b1 = 0.2169, b3 = -0.0082, b5 = 0.00016583, b7 = -0.0000011956;
    vector<double> vector_b0 {b0};
    vector<double> vector_b1 {b1};
    vector<double> vector_b3 {b3};
    vector<double> vector_b5 {b5};
    vector<double> vector_b7 {b7};
    vector<vector<double>> coeff(5, vector<double>(1));
    coeff.at(0) = vector_b0;
    coeff.at(1) = vector_b1;
    coeff.at(2) = vector_b3;
    coeff.at(3) = vector_b5;
    coeff.at(4) = vector_b7;

    vector<Plaintext> plain_sigmoid_coeff(coeff.size());
    print_line(__LINE__);
    cout << "Sigmoid function evaluation" << endl;
    cout << "    + coeffs of sigmoid: " << "b0, b1, b3, b5, b7 are " << b0 << ", " << b1 << ", " << b3 << ", " << b5 << ", " << b7 << endl;
    // coeff: + encode
    for (size_t i=0; i<coeff.size(); i++)
        encoder.encode(coeff.at(i), scale, plain_sigmoid_coeff.at(i));
 
    // tmp Ciphertext
    Ciphertext tmp;
    // + x^3, x^5, x&7
    vector<Ciphertext> encrypted_x3_vector(num_L_init), encrypted_x5_vector(num_L_init), encrypted_x7_vector(num_L_init);
    
    for (size_t i=0; i<num_L_init; i++){

        cout << "x^3 evaluation" << endl;
        evaluator.square(encrypted_L_init_vector.at(i), tmp);
        evaluator.relinearize_inplace(tmp, relin_keys);
        evaluator.rescale_to_next_inplace(tmp);    

        evaluator.mod_switch_to_inplace(encrypted_L_init_vector.at(i), tmp.parms_id());
        evaluator.multiply(tmp, encrypted_L_init_vector.at(i), encrypted_x3_vector.at(i));
        evaluator.relinearize_inplace(encrypted_x3_vector.at(i), relin_keys);
        evaluator.rescale_to_next_inplace(encrypted_x3_vector.at(i));
        cout << "    + modulus chain index for encrypted_L_init_vector.at(i): " << context.get_context_data(encrypted_L_init_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;

        // x^5
        cout << "x^5 evaluation" << endl;
        evaluator.mod_switch_to_inplace(tmp, encrypted_x3_vector.at(i).parms_id());
        evaluator.multiply(encrypted_x3_vector.at(i), tmp, encrypted_x5_vector.at(i)); // tmp is x^2
        evaluator.relinearize_inplace(encrypted_x5_vector.at(i), relin_keys);
        evaluator.rescale_to_next_inplace(encrypted_x5_vector.at(i));    
        cout << "    + modulus chain index for encrypted_x5_vector.at(i): " << context.get_context_data(encrypted_x5_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;

        // x^7
        cout << "x^7 evaluation" << endl;
        evaluator.mod_switch_to_inplace(tmp, encrypted_x5_vector.at(i).parms_id());
        evaluator.multiply(encrypted_x5_vector.at(i), tmp, encrypted_x7_vector.at(i)); // tmp is x^2
        evaluator.relinearize_inplace(encrypted_x7_vector.at(i), relin_keys);
        evaluator.rescale_to_next_inplace(encrypted_x7_vector.at(i));    
        cout << "    + modulus chain index for encrypted_x7_vector.at(i): " << context.get_context_data(encrypted_x7_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;

        cout << "Multiply by coefficients" << endl;
        // b1 * x
        evaluator.mod_switch_to_inplace(plain_sigmoid_coeff.at(1), encrypted_L_init_vector.at(i).parms_id());
        evaluator.multiply_plain_inplace(encrypted_L_init_vector.at(i), plain_sigmoid_coeff.at(1));
        evaluator.rescale_to_next_inplace(encrypted_L_init_vector.at(i));
        // b3 * x^3
        evaluator.mod_switch_to_inplace(plain_sigmoid_coeff.at(2), encrypted_x3_vector.at(i).parms_id());
        evaluator.multiply_plain_inplace(encrypted_x3_vector.at(i), plain_sigmoid_coeff.at(2));
        evaluator.rescale_to_next_inplace(encrypted_x3_vector.at(i));
        // b5 * x^5
        evaluator.mod_switch_to_inplace(plain_sigmoid_coeff.at(3), encrypted_x5_vector.at(i).parms_id());
        evaluator.multiply_plain_inplace(encrypted_x5_vector.at(i), plain_sigmoid_coeff.at(3));
        evaluator.rescale_to_next_inplace(encrypted_x5_vector.at(i));
        cout << "    + modulus chain index for encrypted_x5_vector.at(i) multiplied by plain_coeff_b5: " << context.get_context_data(encrypted_x5_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;
        // b7 * x^7
        evaluator.mod_switch_to_inplace(plain_sigmoid_coeff.at(4), encrypted_x7_vector.at(i).parms_id());
        evaluator.multiply_plain_inplace(encrypted_x7_vector.at(i), plain_sigmoid_coeff.at(4));
        evaluator.rescale_to_next_inplace(encrypted_x7_vector.at(i));
        cout << "    + modulus chain index for encrypted_x7_vector.at(i) multiplied by plain_coeff_b7: " << context.get_context_data(encrypted_x7_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;
        // sum all together
        cout << "sum all together" << endl;
        // + first, all on the same floor
        Plaintext plain_tmp;
        evaluator.mod_switch_to(plain_sigmoid_coeff.at(1), encrypted_x7_vector.at(i).parms_id(), plain_tmp); // b0
        evaluator.mod_switch_to_inplace(encrypted_L_init_vector.at(i), encrypted_x7_vector.at(i).parms_id()); // b1 * x
        evaluator.mod_switch_to_inplace(encrypted_x3_vector.at(i), encrypted_x7_vector.at(i).parms_id()); // b3 * x^3
        evaluator.mod_switch_to_inplace(encrypted_x5_vector.at(i), encrypted_x7_vector.at(i).parms_id()); // b5 * x^5

        // + sum all
        cout << "    + scale of encrypted_L_init_vector.at(1): " << log2(encrypted_L_init_vector.at(i).scale()) << " bits" << endl;
        cout << "    + scale of encrypted_x3_vector.at(1): " << log2(encrypted_x3_vector.at(i).scale()) << " bits" << endl;
        cout << "    + scale of encrypted_x5_vector.at(1): " << log2(encrypted_x5_vector.at(i).scale()) << " bits" << endl;
        cout << "    + scale of encrypted_x7_vector.at(1): " << log2(encrypted_x7_vector.at(i).scale()) << " bits" << endl;

        // since their scales are different by little or approximately the same, we scale it to a fixed number
        encrypted_L_init_vector.at(i).scale() = scale;
        encrypted_x3_vector.at(i).scale() = scale;
        encrypted_x5_vector.at(i).scale() = scale;
        encrypted_x7_vector.at(i).scale() = scale;

        evaluator.add_plain_inplace(encrypted_L_init_vector.at(i), plain_tmp);
        evaluator.add_inplace(encrypted_L_init_vector.at(i), encrypted_x3_vector.at(i));
        evaluator.add_inplace(encrypted_L_init_vector.at(i), encrypted_x5_vector.at(i));
        evaluator.add_inplace(encrypted_L_init_vector.at(i), encrypted_x7_vector.at(i));
        cout << "    + modulus chain index for encrypted_L_init_vector.at " << i << " after summing all: " << context.get_context_data(encrypted_L_init_vector.at(i).parms_id())->chain_index() 
         << " floor" << endl;

    }

    return encrypted_L_init_vector;

}

vector<Ciphertext> ckks_preprocess(vector<Ciphertext> encrypted_L_init_vector, double scale, EncryptionParameters parms, GaloisKeys gal_keys){

    SEALContext context(parms);
    Evaluator evaluator(context);

    for (size_t i=0;i<encrypted_L_init_vector.size(); i++){
        evaluator.rotate_vector_inplace(encrypted_L_init_vector.at(i), -i, gal_keys);
    }
    return encrypted_L_init_vector;
}