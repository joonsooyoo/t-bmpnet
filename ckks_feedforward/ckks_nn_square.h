using namespace std;
using namespace seal;

/*
function:
    
    (1) matrix mult
    (2) x^2 by ckks method
    (3) ckks_preprocess 
*/

vector<Ciphertext> ckks_matrix_mult(vector<Ciphertext> encrypted_init_vector, vector<Ciphertext> encrypted_weight_matrix, vector<Ciphertext> encrypted_result_vector, EncryptionParameters parms, RelinKeys relin_keys, GaloisKeys gal_keys);
vector<Ciphertext> ckks_preprocess(vector<Ciphertext> encrypted_L_init_vector, double scale, EncryptionParameters parms, GaloisKeys gal_keys);

vector<Ciphertext> ckks_square(vector<Ciphertext> encrypted_L_init_vector, double scale, EncryptionParameters parms, RelinKeys relin_keys);



void ckks_nn_square(){

    float start, end;
	// start time
	start = clock();

	print_example_banner("ckks ckks_experiment6: feedforward NN with layers [3, 4, 5, 2] using x^2 as an activation function");
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
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40 }));
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40 }));
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

    /***** ckks_x^2 *****/
    encrypted_L1_vector = ckks_square(encrypted_L1_vector, scale, parms, relin_keys);

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

    cout << "    + scale of encrypted_input: " << log2(encrypted_weight_matrix_L1_to_L2.at(0).scale()) << " bits" << endl;
    cout << "    + modulus chain index for encrypted_input: " << context.get_context_data(encrypted_weight_matrix_L1_to_L2.at(0).parms_id())->chain_index() 
         << " floor" << endl;
    
    print_line(__LINE__);
    cout << "Multiplication W * x" << endl;
    // + next input_encrypted: encrypted_L2_vector
    vector<Ciphertext> encrypted_L2_vector(num_L2);
     
    /***** evaluation of weight_matrix_L1_to_L2 * L1_vector *****/
    encrypted_L2_vector = ckks_matrix_mult(encrypted_L1_vector, encrypted_weight_matrix_L1_to_L2, encrypted_L2_vector, parms, relin_keys, gal_keys);
    cout << "    + modulus chain index for encrypted_L2_vector.at(0): " << context.get_context_data(encrypted_L2_vector.at(0).parms_id())->chain_index() 
     << " floor" << endl;

    // + decrypt
    vector<Plaintext> plain_L2_vector(num_L2);
    vector<vector<double>> result_vector_2(num_L2, vector<double>(slot_count));
   
    for (size_t i=0; i<encrypted_L2_vector.size(); i++)
       decryptor.decrypt(encrypted_L2_vector.at(i), plain_L2_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_L2_vector.size(); i++)
        encoder.decode(plain_L2_vector.at(i), result_vector_2.at(i));
    for (size_t i=0; i<plain_L2_vector.size(); i++){
        cout << "L2_" << i+1 << ": " << endl;
        print_vector(result_vector_2.at(i));
    }

    /***** addition by (encrypted) bias *****/
    print_line(__LINE__);
    cout << "Bias at L2 is added" << endl;
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
    for (size_t i=0; i<encrypted_L2_vector.size(); i++)
       decryptor.decrypt(encrypted_L2_vector.at(i), plain_L2_vector.at(i));
    // + decode
    for (size_t i=0; i<plain_L2_vector.size(); i++)
        encoder.decode(plain_L2_vector.at(i), result_vector_2.at(i));
    for (size_t i=0; i<plain_L2_vector.size(); i++){
        cout << "L2_" << i+1 << ": " << endl;
        print_vector(result_vector_2.at(i));
    }
    /***** ckks_x^2 *****/
    encrypted_L2_vector = ckks_square(encrypted_L2_vector, scale, parms, relin_keys);

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
    /***** ckks_x^2 *****/
    encrypted_Output_vector = ckks_square(encrypted_Output_vector, scale, parms, relin_keys);

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

vector<Ciphertext> ckks_square(vector<Ciphertext> encrypted_L_init_vector, double scale, EncryptionParameters parms, RelinKeys relin_keys){

    SEALContext context(parms);
    Evaluator evaluator(context);

    for (size_t i=0; i<encrypted_L_init_vector.size(); i++){

        evaluator.square_inplace(encrypted_L_init_vector.at(i));
        evaluator.relinearize_inplace(encrypted_L_init_vector.at(i), relin_keys);
        evaluator.rescale_to_next_inplace(encrypted_L_init_vector.at(i));
    }

    // set the scale to be equal to the original scale
    for (size_t i=0; i<encrypted_L_init_vector.size(); i++)
        encrypted_L_init_vector.at(i).scale() = scale;    

    return encrypted_L_init_vector;

}
