#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

/*************************  Basic Operations  *************************/
///////////////////////////////     2's compliment     ////////////////////////////
//res = -a

void HomTwosCompliment(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);	    
	LweSample* b = new_gate_bootstrapping_ciphertext_array(length, bk->params);	    

	bootsCONSTANT(&b[0], 1, bk);
    

	for(int i = 0; i < length - 2; i++){
		bootsNOT(&temp[0], &a[i], bk);
		bootsXOR(&res[i], &temp[0], &b[i], bk);
		bootsAND(&b[i+1], &temp[0], &b[i], bk);}

	bootsNOT(&temp[0], &a[length-2], bk);
	bootsXOR(&res[length-2], &temp[0], &b[length-2], bk);

	bootsNOT(&res[length-1], &a[length-1], bk);
	

	delete_gate_bootstrapping_ciphertext_array(length, b);    
	delete_gate_bootstrapping_ciphertext_array(1, temp);    
}

///////////////////////////////     left shift     ////////////////////////////

void HomLShift(LweSample* res, const LweSample* a, const int length, const int k, const TFheGateBootstrappingCloudKeySet* bk) {

	for(int i = 0; i < length - k; i++){
		bootsCOPY(&res[i], &a[i+k], bk);}
	for(int i = length-k; i < length; i++){
		bootsCOPY(&res[i], &a[length-1], bk);}
}

///////////////////////////////     right shift     ////////////////////////////

void HomRShift(LweSample* res, const LweSample* a, const int length, const int k, const TFheGateBootstrappingCloudKeySet* bk) {

	for(int i = 0; i < k; i++){
		bootsCONSTANT(&res[i], 0, bk);}
	for(int i = k; i < length; i++){
		bootsCOPY(&res[i], &a[i-k], bk);}
}

///////////////////////////////     equivalent or not     ////////////////////////////
// if a = b then res = E(1)
// else res = E(0)

void HomEqui(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);	    

	bootsCONSTANT(&temp[0], 1, bk);
	for(int i = 0; i < length; i++){		
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsAND(&temp[0], &temp[0], &temp[1], bk);
		
	}
	bootsCOPY(&res[0], &temp[0], bk);

	delete_gate_bootstrapping_ciphertext_array(2, temp);
}

///////////////////////////////     big comparison     ////////////////////////////
// if a > b then res = E(1)
// else res = E(0)

void HomCompB(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &a[i], bk);}

	bootsCOPY(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}

///////////////////////////////     small comparison     ////////////////////////////
// if a < b then res = E(1)
// else res = E(0)

void HomCompS(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &b[i], bk);}

	bootsCOPY(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}

///////////////////////////////     smaller than or equal to comparison     ////////////////////////////

void HomCompSE(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &a[i], bk);}

	bootsNOT(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}

///////////////////////////////     larger than or equal to comparison     ////////////////////////////

void HomCompLE(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &b[i], bk);}

	bootsNOT(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}

///////////////////////////////     maximum     ////////////////////////////
// if a > b then res = a

void HomMax(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	
	HomCompB(&temp[0], a, b, length, bk);

	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &temp[0], &a[i], &b[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(1, temp);
}

///////////////////////////////     minimum     ////////////////////////////
// if a < b then res = a

void HomMin(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	
	HomCompS(&temp[0], a, b, length, bk);

	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &temp[0], &a[i], &b[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(1, temp);
}

///////////////////////////////     absolute value     ////////////////////////////
// if a < b then res = a

void HomAbs(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* na = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomTwosCompliment(na, a, length, bk);
	
	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &a[length-1], &na[i], &a[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(length, na);
}

///////////////////////////////     plaintext to ciphertext     ////////////////////////////

void HomP2C(LweSample* res, const int num, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(5, bk->params);

	
	int8_t plain = num;

	for(int i = 0; i < length; i++)
		bootsCONSTANT(&res[i], (plain>>i)&1, bk);


	delete_gate_bootstrapping_ciphertext_array(1, temp);
}

///////////////////////////////     plaintext to ciphertext     ////////////////////////////

void HomRealP2C(LweSample* res, const int num, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(5, bk->params);

	int16_t plain = num;

	for(int i = 0; i < (length/2)-1; i++)
		bootsCONSTANT(&res[i], 0, bk);
	for(int i = 0; i < (length/2)+1; i++)
		bootsCONSTANT(&res[i+(length/2)-1], (plain>>i)&1, bk);

	delete_gate_bootstrapping_ciphertext_array(1, temp);
}

/*************************  4 Fundamental Operations  *************************/
///////////////////////////////     Addition     ////////////////////////////
//res = a + b

void HomAdd(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* c = new_gate_bootstrapping_ciphertext_array(length, bk->params);	    
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);	    

	bootsCONSTANT(&c[0], 0, bk);
    
	for(int i = 0; i < length -1; i++){
		bootsXOR(&temp[0], &a[i], &b[i], bk);
		bootsAND(&temp[1], &a[i], &b[i], bk);
		bootsXOR(&res[i], &temp[0], &c[i], bk);
		bootsAND(&temp[0], &temp[0], &c[i], bk);
		bootsOR(&c[i+1], &temp[0], &temp[1], bk);
	}

	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsXOR(&res[length-1], &temp[0], &c[length-1], bk);

	delete_gate_bootstrapping_ciphertext_array(length, c);    
	delete_gate_bootstrapping_ciphertext_array(2, temp);    
}

///////////////////////////////     Subtraction     ////////////////////////////
//res = a - b

void HomSubt(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* c = new_gate_bootstrapping_ciphertext_array(length, bk->params);	    
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);	    

	bootsCONSTANT(&c[0], 0, bk);
    
	for(int i = 0; i < length -1; i++){
		bootsXOR(&temp[0], &a[i], &b[i], bk);
		bootsXOR(&res[i], &temp[0], &c[i], bk);
		bootsANDNY(&temp[1], &a[i], &b[i], bk);
		bootsANDNY(&temp[0], &temp[0], &c[i], bk);
		bootsOR(&c[i+1], &temp[1], &temp[0], bk);} 

	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsXOR(&res[length-1], &temp[0], &c[length-1], bk);

	delete_gate_bootstrapping_ciphertext_array(length, c);    
	delete_gate_bootstrapping_ciphertext_array(2, temp);    
}

///////////////////////////////   Multiplication(Integer)    ////////////////////////////
//res = a * b
//with addition(length * length = 2*length)

void HomMulti(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* AA = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* D = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* F = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomAbs(A, a, length, bk);
	HomAbs(B, b, length, bk);
	
	for(int i = 0; i < length; i++){
		bootsCOPY(&AA[i], &A[i], bk);
		bootsCONSTANT(&C[length+i], 0, bk);
	}

	for(int i = 1; i < length-1; i++){
		HomRShift(C, A, length+i, i, bk);

		for(int j = 0; j < length+i; j++)
			bootsAND(&D[j], &C[j], &B[i], bk);

		HomAdd(AA, AA, D, length+i, bk);}

	for(int i = 0; i < length-1; i++){
		bootsCOPY(&E[i], &AA[i+(length/2)-1], bk);}
	bootsCONSTANT(&E[length-1], 0, bk);

	HomTwosCompliment(F, E, length, bk);
	
	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsNOT(&temp[1], &temp[0], bk);

	for(int i = 0; i < length; i++){
		bootsAND(&E[i], &E[i], &temp[1], bk);
		bootsAND(&F[i], &F[i], &temp[0], bk);}

	HomAdd(res, E, F, length, bk);


	delete_gate_bootstrapping_ciphertext_array(2, temp);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(2*length, AA);
	delete_gate_bootstrapping_ciphertext_array(length, B);
	delete_gate_bootstrapping_ciphertext_array(2*length, C);
	delete_gate_bootstrapping_ciphertext_array(2*length, D);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, F);
}

///////////////////////////////     Multiplication(Real Number)     ////////////////////////////
//res = a * b 

void HomMultiReal(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* AA = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* D = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* F = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomAbs(A, a, length, bk);
	HomAbs(B, b, length, bk);
	for(int i = 0; i < length; i++){
		bootsAND(&AA[i], &A[i], &B[0], bk);}
	HomLShift(AA, AA, length, length/2 - 1, bk);	
	
	for(int i = 1; i < length-1; i++){
		if(i < length/2 - 1){
			HomLShift(C, A, length, length/2-1-i, bk);

			for(int j = 0; j < length; j++)
				bootsAND(&D[j], &C[j], &B[i], bk);

			HomAdd(AA, AA, D, length, bk);
		}
		else if(i == length/2 - 1){
			for(int j = 0; j < length; j++)
				bootsAND(&D[j], &A[j], &B[i], bk);

			HomAdd(AA, AA, D, length, bk);
		}

		else {
			HomRShift(C, A, length, i-length/2 + 1, bk);
			for(int j = 0; j < length; j++){
				bootsAND(&D[j], &C[j], &B[i], bk);}

			HomAdd(AA, AA, D, length, bk);
		}

	}
	bootsCONSTANT(&AA[length-1], 0, bk);

	HomTwosCompliment(D, AA, length, bk);
	
	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsNOT(&temp[1], &temp[0], bk);

	for(int i = 0; i < length; i++){
		bootsAND(&E[i], &AA[i], &temp[1], bk);
		bootsAND(&F[i], &D[i], &temp[0], bk);}

	HomAdd(res, E, F, length, bk);

	delete_gate_bootstrapping_ciphertext_array(2, temp);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(length, AA);
	delete_gate_bootstrapping_ciphertext_array(length, B);
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, D);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, F);
}

///////////////////////////////     Division     ////////////////////////////
// a / (-b)  =>  (-a) / b
// (-a) / (-b)  =>  a / b
// length = 2 * length
// res1 = Quotient
// res2 = Remainder

void HomDiv(LweSample* res1, LweSample* res2, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(3, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* QR = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* D = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Q = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* DD = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* R = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E0 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomAbs(A, a, length, bk);
	HomAbs(B, b, length, bk);

	for(int i = 0; i < length; i++){
		bootsCOPY(&QR[i], &A[i], bk);
		bootsCOPY(&D[i], &B[i], bk);
		bootsCONSTANT(&QR[length + i], 0, bk);}
	

	HomRShift(QR, QR, 2*length, 1, bk);
	for(int s = 1; s < length; s++){
		HomRShift(QR, QR, 2*length, 1, bk);

		for(int i = 0; i < length; i++){
			bootsCOPY(&R[i], &QR[length+i], bk);}

		HomCompS(&temp[0], R, D, length, bk);
		bootsNOT(&temp[1], &temp[0], bk);
		bootsCOPY(&QR[0], &temp[1], bk);

		for(int i = 0; i < length; i++){
			bootsAND(&DD[i], &D[i], &temp[1], bk);}

		HomSubt(R, R, DD, length, bk);

		for(int i = 0; i < length; i++){
			bootsCOPY(&QR[length+i], &R[i], bk);}
	}
		


	for(int i = 0; i < length; i++){
		bootsCOPY(&Q[i], &QR[i], bk);
		bootsCOPY(&res2[i], &QR[length+i], bk);}



	HomTwosCompliment(C, Q, length, bk);
	
	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsNOT(&temp[1], &temp[0], bk);

	for(int i = 0; i < length; i++){
		bootsAND(&Q[i], &Q[i], &temp[1], bk);
		bootsAND(&C[i], &C[i], &temp[0], bk);}

	HomAdd(Q, Q, C, length, bk);

	for(int i = 0; i < length; i++){
		bootsCONSTANT(&E0[i], 0, bk);}

	HomEqui(&temp[0], res2, E0, length, bk);

	bootsNOT(&E0[0], &temp[0], bk);

	HomSubt(res1, Q, E0, length, bk);
	printf("division clear\n");


	delete_gate_bootstrapping_ciphertext_array(3, temp);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(length, B);
	delete_gate_bootstrapping_ciphertext_array(2*length, QR);
	delete_gate_bootstrapping_ciphertext_array(length, D);
	delete_gate_bootstrapping_ciphertext_array(length, DD);
	delete_gate_bootstrapping_ciphertext_array(length, Q);
	delete_gate_bootstrapping_ciphertext_array(length, R);
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, E0);
}









///////////////////////////////     Logarithm  16 bit   ////////////////////////////
// log base a of b

void HomLog16(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* Setting = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* out_sum = new_gate_bootstrapping_ciphertext_array((length/2)+1, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array((length/2)+1, bk->params);
	LweSample* p = new_gate_bootstrapping_ciphertext_array((length/2)+1, bk->params);
	LweSample* S = new_gate_bootstrapping_ciphertext_array((length/2)+1, bk->params);
	LweSample* sf = new_gate_bootstrapping_ciphertext_array((length/2)+1, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* MC = new_gate_bootstrapping_ciphertext_array(2*length+1, bk->params);
	LweSample* lb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x= new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nMC = new_gate_bootstrapping_ciphertext_array(1, bk->params);

	//// find digit of 'b'
	// fill Setting with zeroes
	for(int j = 0; j < length; j++){
		bootsCONSTANT(&Setting[j], 0, bk);
	}

	for(int i = 0; i < length-1; i++){			//compare Setting with the b
		bootsCONSTANT(&Setting[i], 1, bk);
		HomCompLE(&Output[i], b, Setting, length, bk);		//store outcomes in Output array
		bootsCONSTANT(&Setting[i], 0, bk);
	}
	// Sum of the Output
	for(int i = 0; i < (length/2)+1; i++){
		bootsCONSTANT(&out_sum[i], 0 , bk);
		bootsCONSTANT(&temp[i], 0 , bk);
	}

	// Initialize
	for(int i = 0; i < length-1; i++){
		bootsCOPY(&temp[0], &Output[i] , bk);	
		HomAdd(out_sum, out_sum, temp, (length/2)+1, bk);
	}

	//// Position of b
	// make 8 : subtraction factor
	for(int i = 0; i < (length/2)+1; i++){
		bootsCONSTANT(&p[i], 0 , bk);}
	
	bootsCONSTANT(&p[3], 1 , bk);
	

	// subtraction
		HomSubt(out_sum, out_sum, p, 5, bk);

	// Shift variable array : S = 7
	for(int i = 0; i < 3; i++){
		bootsCONSTANT(&S[i], 1, bk);}

	for(int i = 3; i < 5; i++){
		bootsCONSTANT(&S[i], 0, bk);}

	// Subtracting factor array : sf = 1
	for(int i = 1; i < 5; i++){
		bootsCONSTANT(&sf[i], 0, bk);} 

		bootsCONSTANT(&sf[0], 1, bk);

	// find a position of b
	for(int i = 0; i < length; i++)
		bootsCONSTANT(&C[i], 0, bk);

	for(int i = 0; i < (length/2)-2; i++){

		HomSubt(S, S, sf, 5, bk);

		HomEqui(&E[i], S, out_sum, 5, bk); 
		
		HomLShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i], bk);

		HomAdd(C, A, C, length, bk);

		}



	HomSubt(S, S, sf, 5, bk);
/*
	for(int i = 0; i < 5; i++)
		bootsCOPY(&res[i], &S[i], bk);
*/
	HomEqui(&E[6], S, out_sum, 5, bk); 

	for(int j = 0; j < length; j++)
		bootsAND(&A[j], &b[j], &E[6], bk);

	HomAdd(C, A, C, length, bk);

	for(int i = 0; i < 5; i++)
		bootsCOPY(&res[i], &S[i], bk);

	for(int i = 0; i < (length/2)-1; i++){

		HomSubt(S, S, sf, 5, bk);
		HomEqui(&E[i+7], S, out_sum, 5, bk); 
		
		HomRShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i+7], bk);

		HomAdd(C, A, C, length, bk);

	}	

	////logarithm of shifted 'b'
	// build up last array : final	
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&final[i], 0, bk);
}
	for(int j = 0; j < 7; j++){
	HomMulti(MC, C, C, length, bk);
	
	bootsCOPY(&final[6-j], &MC[8], bk);

	HomLShift(lb, C, length, 1, bk);
	for(int i = 0; i < length; i++){
		bootsAND(&x[i], &MC[8], &lb[i], bk); 
}
	// not mc[8]
	bootsNOT(&nMC[0], &MC[8], bk);
	for(int i = 0; i < length; i++){
		bootsAND(&nx[i], &nMC[0], &C[i], bk);
	}

	HomAdd(C, x, nx, length, bk);
}
	// integer part of log 2 of b
	for(int i = 0; i < 4; i++){
	bootsCOPY(&final[i+7], &out_sum[i], bk);
}
	bootsCOPY(&final[15], &out_sum[4], bk);

	// result of log base 2 of b 
	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &final[i], bk);
}

	delete_gate_bootstrapping_ciphertext_array(length, Setting);
	delete_gate_bootstrapping_ciphertext_array(length, Output);
	delete_gate_bootstrapping_ciphertext_array(5, out_sum);
	delete_gate_bootstrapping_ciphertext_array(5, temp);
	delete_gate_bootstrapping_ciphertext_array(5, p);
	delete_gate_bootstrapping_ciphertext_array(5, S);
	delete_gate_bootstrapping_ciphertext_array(5, sf);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, A);	
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, final);
	delete_gate_bootstrapping_ciphertext_array(2*length+1, MC);
	delete_gate_bootstrapping_ciphertext_array(length, lb);
	delete_gate_bootstrapping_ciphertext_array(length, x);
	delete_gate_bootstrapping_ciphertext_array(length, nx);
	delete_gate_bootstrapping_ciphertext_array(1, nMC);
}

///////////////////////////////     Logarithm  8 bit  ////////////////////////////
// log base a of b

void HomLog8(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* Setting = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* out_sum = new_gate_bootstrapping_ciphertext_array(5, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(5, bk->params);
	LweSample* p = new_gate_bootstrapping_ciphertext_array(5, bk->params);
	LweSample* S = new_gate_bootstrapping_ciphertext_array(5, bk->params);
	LweSample* sf = new_gate_bootstrapping_ciphertext_array(5, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* MC = new_gate_bootstrapping_ciphertext_array(2*length+1, bk->params);
	LweSample* lb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x= new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nMC = new_gate_bootstrapping_ciphertext_array(1, bk->params);

	//// find digit of 'b'
	// fill Setting with zeroes
	for(int j = 0; j < length; j++){
		bootsCONSTANT(&Setting[j], 0, bk);
	}

	for(int i = 0; i < length-1; i++){			//compare Setting with the b
		bootsCONSTANT(&Setting[i], 1, bk);
		HomCompLE(&Output[i], b, Setting, length, bk);		//store outcomes in Output array
		bootsCONSTANT(&Setting[i], 0, bk);
	}
	// Sum of the Output
	for(int i = 0; i < 5; i++){
		bootsCONSTANT(&out_sum[i], 0 , bk);
		bootsCONSTANT(&temp[i], 0 , bk);
	}

	// Initialize
	for(int i = 0; i < length-1; i++){
		bootsCOPY(&temp[0], &Output[i] , bk);	
		HomAdd(out_sum, out_sum, temp, 5, bk);
	}

	//// Position of b
	// make 8 : subtraction factor
	for(int i = 0; i < 5; i++){
		bootsCONSTANT(&p[i], 0 , bk);}
	
	bootsCONSTANT(&p[2], 1 , bk);
	

	// subtraction
		HomSubt(out_sum, out_sum, p, 5, bk);

	// Shift variable array : S = 3
	for(int i = 0; i < 2; i++){
		bootsCONSTANT(&S[i], 1, bk);}

	for(int i = 2; i < 5; i++){
		bootsCONSTANT(&S[i], 0, bk);}

	// Subtracting factor array : sf = 1
	for(int i = 1; i < 5; i++){
		bootsCONSTANT(&sf[i], 0, bk);} 

		bootsCONSTANT(&sf[0], 1, bk);

	// find a position of b
	for(int i = 0; i < length; i++)
		bootsCONSTANT(&C[i], 0, bk);

	for(int i = 0; i < (length/2)-1; i++){

		HomSubt(S, S, sf, 5, bk);

		HomEqui(&E[i], S, out_sum, 5, bk); 
		
		HomLShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i], bk);

		HomAdd(C, A, C, length, bk);

		}



	HomSubt(S, S, sf, 5, bk);
/*
	for(int i = 0; i < 5; i++)
		bootsCOPY(&res[i], &S[i], bk);
*/
	HomEqui(&E[2], S, out_sum, 5, bk); 

	for(int j = 0; j < length; j++)
		bootsAND(&A[j], &b[j], &E[2], bk);

	HomAdd(C, A, C, length, bk);

	for(int i = 0; i < 5; i++)
		bootsCOPY(&res[i], &S[i], bk);

	for(int i = 0; i < (length/2)-1; i++){

		HomSubt(S, S, sf, 5, bk);
		HomEqui(&E[i+3], S, out_sum, 5, bk); 
		
		HomRShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i+3], bk);

		HomAdd(C, A, C, length, bk);

	}	

	////logarithm of shifted 'b'
	// build up last array : final	
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&final[i], 0, bk);
}
	for(int j = 0; j < 3; j++){
	HomMulti(MC, C, C, length, bk);
	
	bootsCOPY(&final[2-j], &MC[4], bk);

	HomLShift(lb, C, length, 1, bk);
	for(int i = 0; i < length; i++){
		bootsAND(&x[i], &MC[4], &lb[i], bk); 
}
	// not mc[4]
	bootsNOT(&nMC[0], &MC[4], bk);
	for(int i = 0; i < length; i++){
		bootsAND(&nx[i], &nMC[0], &C[i], bk);
	}

	HomAdd(C, x, nx, length, bk);
}
	// integer part of log 2 of b
	for(int i = 0; i < 4; i++){
	bootsCOPY(&final[i+3], &out_sum[i], bk);
}
	bootsCOPY(&final[7], &out_sum[4], bk);

	// result of log base 2 of b 
	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &final[i], bk);
}

	delete_gate_bootstrapping_ciphertext_array(length, Setting);
	delete_gate_bootstrapping_ciphertext_array(length, Output);
	delete_gate_bootstrapping_ciphertext_array(5, out_sum);
	delete_gate_bootstrapping_ciphertext_array(5, temp);
	delete_gate_bootstrapping_ciphertext_array(5, p);
	delete_gate_bootstrapping_ciphertext_array(5, S);
	delete_gate_bootstrapping_ciphertext_array(5, sf);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, A);	
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, final);
	delete_gate_bootstrapping_ciphertext_array(2*length+1, MC);
	delete_gate_bootstrapping_ciphertext_array(length, lb);
	delete_gate_bootstrapping_ciphertext_array(length, x);
	delete_gate_bootstrapping_ciphertext_array(length, nx);
	delete_gate_bootstrapping_ciphertext_array(1, nMC);
}



///////////////////////////////     Logarithm  32 bit  ////////////////////////////
// log base a of b

void HomLog32(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* Setting = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* out_sum = new_gate_bootstrapping_ciphertext_array(6, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(6, bk->params);
	LweSample* p = new_gate_bootstrapping_ciphertext_array(6, bk->params);
	LweSample* S = new_gate_bootstrapping_ciphertext_array(6, bk->params);
	LweSample* sf = new_gate_bootstrapping_ciphertext_array(6, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* MC = new_gate_bootstrapping_ciphertext_array(2*length+1, bk->params);
	LweSample* lb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x= new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nMC = new_gate_bootstrapping_ciphertext_array(1, bk->params);

	//// find digit of 'b'
	// fill Setting with zeroes
	for(int j = 0; j < length; j++){
		bootsCONSTANT(&Setting[j], 0, bk);
	}

	for(int i = 0; i < length-1; i++){			//compare Setting with the b
		bootsCONSTANT(&Setting[i], 1, bk);
		HomCompLE(&Output[i], b, Setting, length, bk);		//store outcomes in Output array
		bootsCONSTANT(&Setting[i], 0, bk);
	}
	// Sum of the Output
	for(int i = 0; i < 6; i++){
		bootsCONSTANT(&out_sum[i], 0 , bk);
		bootsCONSTANT(&temp[i], 0 , bk);
	}

	// Initialize
	for(int i = 0; i < length-1; i++){
		bootsCOPY(&temp[0], &Output[i] , bk);	
		HomAdd(out_sum, out_sum, temp, 5, bk);
	}

	//// Position of b
	// make 16 : subtraction factor
	for(int i = 0; i < 6; i++){
		bootsCONSTANT(&p[i], 0 , bk);}
	
	bootsCONSTANT(&p[4], 1 , bk);
	

	// subtraction
		HomSubt(out_sum, out_sum, p, 5, bk);

	// Shift variable array : S = 15
	for(int i = 0; i < 4; i++){
		bootsCONSTANT(&S[i], 1, bk);}

	for(int i = 4; i < 6; i++){
		bootsCONSTANT(&S[i], 0, bk);}

	// Subtracting factor array : sf = 1
	for(int i = 1; i < 6; i++){
		bootsCONSTANT(&sf[i], 0, bk);} 

		bootsCONSTANT(&sf[0], 1, bk);

	// find a position of b
	for(int i = 0; i < length; i++)
		bootsCONSTANT(&C[i], 0, bk);

	for(int i = 0; i < (length/2)-1; i++){

		HomSubt(S, S, sf, 6, bk);

		HomEqui(&E[i], S, out_sum, 6, bk); 
		
		HomLShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i], bk);

		HomAdd(C, A, C, length, bk);

		}



	HomSubt(S, S, sf, 6, bk);
/*
	for(int i = 0; i < 5; i++)
		bootsCOPY(&res[i], &S[i], bk);
*/
	HomEqui(&E[15], S, out_sum, 6, bk); 

	for(int j = 0; j < length; j++)
		bootsAND(&A[j], &b[j], &E[15], bk);

	HomAdd(C, A, C, length, bk);

	for(int i = 0; i < 6; i++)
		bootsCOPY(&res[i], &S[i], bk);

	for(int i = 0; i < (length/2); i++){

		HomSubt(S, S, sf, 6, bk);
		HomEqui(&E[i+16], S, out_sum, 5, bk); 
		
		HomRShift(A, b, length, i+1, bk);

		for(int j = 0; j < length; j++)
			bootsAND(&A[j], &A[j], &E[i+16], bk);

		HomAdd(C, A, C, length, bk);

	}	

	////logarithm of shifted 'b'
	// build up last array : final	
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&final[i], 0, bk);
}
	for(int j = 0; j < 15; j++){
	HomMulti(MC, C, C, length, bk);
	
	bootsCOPY(&final[15-j], &MC[16], bk);

	HomLShift(lb, C, length, 1, bk);
	for(int i = 0; i < length; i++){
		bootsAND(&x[i], &MC[16], &lb[i], bk); 
}
	
	// not mc[16]
	bootsNOT(&nMC[0], &MC[16], bk);
	for(int i = 0; i < length; i++){
		bootsAND(&nx[i], &nMC[0], &C[i], bk);
	}

	HomAdd(C, x, nx, length, bk);
}
	// integer part of log 2 of b
	for(int i = 0; i < 5; i++){
	bootsCOPY(&final[i+15], &out_sum[i], bk);
}
	bootsCOPY(&final[31], &out_sum[5], bk);

	// result of log base 2 of b 
	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &final[i], bk);
}

	delete_gate_bootstrapping_ciphertext_array(length, Setting);
	delete_gate_bootstrapping_ciphertext_array(length, Output);
	delete_gate_bootstrapping_ciphertext_array(6, out_sum);
	delete_gate_bootstrapping_ciphertext_array(6, temp);
	delete_gate_bootstrapping_ciphertext_array(6, p);
	delete_gate_bootstrapping_ciphertext_array(6, S);
	delete_gate_bootstrapping_ciphertext_array(6, sf);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, A);	
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, final);
	delete_gate_bootstrapping_ciphertext_array(2*length+1, MC);
	delete_gate_bootstrapping_ciphertext_array(length, lb);
	delete_gate_bootstrapping_ciphertext_array(length, x);
	delete_gate_bootstrapping_ciphertext_array(length, nx);
	delete_gate_bootstrapping_ciphertext_array(1, nMC);
}









///////////////////////////////     Logarithm(Taylor series) terms : 5   ////////////////////////////
// log base 2 of b

void HomLogT5(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* sf = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb2 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb3 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb4 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb5 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mbt = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt5 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div5 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_5 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	///////////////// Initialize iteration
	// Subtraction Factor(sf) = 1
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&sf[i], 0, bk);
	}
	bootsCONSTANT(&sf[length/2-1], 1, bk);
	
	//// Build Output array 
	// Output array : O_2, O_3, O_4, O_5
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&O_2[i], 0, bk);
		bootsCONSTANT(&O_3[i], 0, bk);
		bootsCONSTANT(&O_4[i], 0, bk);
		bootsCONSTANT(&O_5[i], 0, bk);
	}
	
	//// temporary array : mbt, mbt2, mbt3,  mbt4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&mbt[i], 0, bk);
		bootsCONSTANT(&mbt2[i], 0, bk);
		bootsCONSTANT(&mbt3[i], 0, bk);
		bootsCONSTANT(&mbt4[i], 0, bk);
	}

	//// division factors : div2, div3, div4, div5 
	// division factor : div2 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div2[i], 0, bk);
	}
	bootsCONSTANT(&div2[length/2], 1, bk);
	// division factor : div3 
	for(int i = 0; i < length; i++){

		bootsCONSTANT(&div3[i], 0, bk);
	}
	bootsCONSTANT(&div3[length/2-1], 1, bk);
	bootsCONSTANT(&div3[length/2], 1, bk);
	// division factor : div4 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div4[i], 0, bk);
	}
	bootsCONSTANT(&div4[length/2+1], 1, bk);
	// division factor : div5 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div5[i], 0, bk);
	}
	bootsCONSTANT(&div5[length/2-1], 1, bk);
	bootsCONSTANT(&div5[length/2+1], 1, bk);
	
	
	/////// STEP1 
	// Multiplication basis : mb = b - sf
	HomSubt(mb, b, sf, length, bk);
	

	/////// STEP2
	HomMulti(mb2, mb, mb, length, bk);
		
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt[i], &mb2[i+length/2], bk);
	}

	// divide by a divisor
	HomDiv(O_2, A, mbt, div2, length, bk);

	
	/////// STEP3
	HomMulti(mb3, mbt, mb, length, bk);
	
	for(int i = 0; i < length; i++){
	bootsCOPY(&mbt2[i], &mb3[i+length/2], bk);
	}
	
	// divide by a divisor
	HomDiv(O_3, A, mbt2, div3, length, bk);


	/////// STEP4
	HomMulti(mb4, mbt2, mb, length, bk);
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt3[i], &mb4[i+length/2], bk);
	}
	
	
	// divide by a divisor
	HomDiv(O_4, A, mbt3, div4, length, bk);


	/////// STEP5
	HomMulti(mb5, mbt3, mb, length, bk);
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt5[i], &mb5[i+length/2], bk);
	}

	
	// divide by a divisor
	HomDiv(O_5, A, mbt3, div5, length, bk);

	/////// Summation of all the output : output
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&output[i], 0, bk);
	}
	
	HomSubt(output, mb, O_2, length, bk);
	HomAdd(output, output, O_3, length, bk);	
	HomSubt(output, output, O_4, length, bk);
	HomAdd(output, output, O_5, length, bk);	

	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &output[i], bk);
	}



	delete_gate_bootstrapping_ciphertext_array(length, sf);
	delete_gate_bootstrapping_ciphertext_array(length, mb);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb2);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb3);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb4);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb5);
	delete_gate_bootstrapping_ciphertext_array(length, mbt);
	delete_gate_bootstrapping_ciphertext_array(length, mbt2);
	delete_gate_bootstrapping_ciphertext_array(length, mbt3);
	delete_gate_bootstrapping_ciphertext_array(length, div2);
	delete_gate_bootstrapping_ciphertext_array(length, div3);
	delete_gate_bootstrapping_ciphertext_array(length, div4);
	delete_gate_bootstrapping_ciphertext_array(length, div5);
	delete_gate_bootstrapping_ciphertext_array(length, O_2);
	delete_gate_bootstrapping_ciphertext_array(length, O_3);
	delete_gate_bootstrapping_ciphertext_array(length, O_4);
	delete_gate_bootstrapping_ciphertext_array(length, O_5);
	delete_gate_bootstrapping_ciphertext_array(length, output);


}



///////////////////////////////     Logarithm(Exponential Approximation) terms : 4   ////////////////////////////
// log base 2 of b

void HomLogT4(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* sf = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb2 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb3 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb4 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mbt = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	///////////////// Initialize iteration
	// Subtraction Factor(sf) = 1
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&sf[i], 0, bk);
	}
	bootsCONSTANT(&sf[length/2-1], 1, bk);
	
	//// Build Output array 
	// Output array : O_2, O_3, O_4, O_5
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&O_2[i], 0, bk);
		bootsCONSTANT(&O_3[i], 0, bk);
		bootsCONSTANT(&O_4[i], 0, bk);
	}
	
	//// temporary array : mbt, mbt2, mbt3,  mbt4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&mbt[i], 0, bk);
		bootsCONSTANT(&mbt2[i], 0, bk);
		bootsCONSTANT(&mbt3[i], 0, bk);
		bootsCONSTANT(&mbt4[i], 0, bk);
	}

	//// division factors : div2, div3, div4 
	// division factor : div2 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div2[i], 0, bk);
	}
	bootsCONSTANT(&div2[length/2], 1, bk);
	// division factor : div3 
	for(int i = 0; i < length; i++){

		bootsCONSTANT(&div3[i], 0, bk);
	}
	bootsCONSTANT(&div3[length/2-1], 1, bk);
	bootsCONSTANT(&div3[length/2], 1, bk);
	// division factor : div4 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div4[i], 0, bk);
	}
	bootsCONSTANT(&div4[length/2+1], 1, bk);
	

	/////// STEP1 
	// Multiplication basis : mb = b - sf
	HomSubt(mb, b, sf, length, bk);
	

	/////// STEP2
	HomMulti(mb2, mb, mb, length, bk);
		
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt[i], &mb2[i+length/2], bk);
	}

	// divide by a divisor
	HomDiv(O_2, A, mbt, div2, length, bk);

	
	/////// STEP3
	HomMulti(mb3, mbt, mb, length, bk);
	
	for(int i = 0; i < length; i++){
	bootsCOPY(&mbt2[i], &mb3[i+length/2], bk);
	}
	
	// divide by a divisor
	HomDiv(O_3, A, mbt2, div3, length, bk);


	/////// STEP4
	HomMulti(mb4, mbt2, mb, length, bk);
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt3[i], &mb4[i+length/2], bk);
	}
	
	
	// divide by a divisor
	HomDiv(O_4, A, mbt3, div4, length, bk);

	/////// Summation of all the output : output
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&output[i], 0, bk);
	}
	
	HomSubt(output, mb, O_2, length, bk);
	HomAdd(output, output, O_3, length, bk);	
	HomSubt(output, output, O_4, length, bk);


	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &output[i], bk);
	}



	delete_gate_bootstrapping_ciphertext_array(length, sf);
	delete_gate_bootstrapping_ciphertext_array(length, mb);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb2);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb3);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb4);
	delete_gate_bootstrapping_ciphertext_array(length, mbt);
	delete_gate_bootstrapping_ciphertext_array(length, mbt2);
	delete_gate_bootstrapping_ciphertext_array(length, mbt3);
	delete_gate_bootstrapping_ciphertext_array(length, mbt4);
	delete_gate_bootstrapping_ciphertext_array(length, div2);
	delete_gate_bootstrapping_ciphertext_array(length, div3);
	delete_gate_bootstrapping_ciphertext_array(length, div4);
	delete_gate_bootstrapping_ciphertext_array(length, O_2);
	delete_gate_bootstrapping_ciphertext_array(length, O_3);
	delete_gate_bootstrapping_ciphertext_array(length, O_4);
	delete_gate_bootstrapping_ciphertext_array(length, output);


}

///////////////////////////////     Logarithm(Exponential Approximation) terms : 3   ////////////////////////////
// log base 2 of b

void HomLogT3(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* sf = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mb2 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mb3 = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* mbt = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mbt3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* div3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* O_3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	///////////////// Initialize iteration
	// Subtraction Factor(sf) = 1
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&sf[i], 0, bk);
	}
	bootsCONSTANT(&sf[length/2-1], 1, bk);

	//// Build Output array 
	// Output array : O_2, O_3, O_4, O_5
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&O_2[i], 0, bk);
		bootsCONSTANT(&O_3[i], 0, bk);
	}
	
	//// temporary array : mbt, mbt2, mbt3,  mbt4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&mbt[i], 0, bk);
		bootsCONSTANT(&mbt2[i], 0, bk);
		bootsCONSTANT(&mbt3[i], 0, bk);
	}

	//// division factors : div2, div3, div4 
	// division factor : div2 
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&div2[i], 0, bk);
	}

	bootsCONSTANT(&div2[length/2], 1, bk);
	// division factor : div3 
	for(int i = 0; i < length; i++){

		bootsCONSTANT(&div3[i], 0, bk);
	}

	bootsCONSTANT(&div3[length/2-1], 1, bk);
	bootsCONSTANT(&div3[length/2], 1, bk);
	

	/////// STEP1 
	// Multiplication basis : mb = b - sf
	HomSubt(mb, b, sf, length, bk);
	

	/////// STEP2
	HomMulti(mb2, mb, mb, length, bk);
		
	for(int i = 0; i < length; i++){
		bootsCOPY(&mbt[i], &mb2[i+length/2], bk);
	}

	// divide by a divisor
	HomDiv(O_2, A, mbt, div2, length, bk);

	
	/////// STEP3
	HomMulti(mb3, mbt, mb, length, bk);
	
	for(int i = 0; i < length; i++){
	bootsCOPY(&mbt2[i], &mb3[i+length/2], bk);
	}
	
	// divide by a divisor
	HomDiv(O_3, A, mbt2, div3, length, bk);


	/////// Summation of all the output : output
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&output[i], 0, bk);
	}
	
	HomSubt(output, mb, O_2, length, bk);
	HomAdd(output, output, O_3, length, bk);	


	for(int i = 0; i < length; i++){
	bootsCOPY(&res[i], &output[i], bk);
	}



	delete_gate_bootstrapping_ciphertext_array(length, sf);
	delete_gate_bootstrapping_ciphertext_array(length, mb);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb2);
	delete_gate_bootstrapping_ciphertext_array(2*length, mb3);
	delete_gate_bootstrapping_ciphertext_array(length, mbt);
	delete_gate_bootstrapping_ciphertext_array(length, mbt2);
	delete_gate_bootstrapping_ciphertext_array(length, mbt3);
	delete_gate_bootstrapping_ciphertext_array(length, div2);
	delete_gate_bootstrapping_ciphertext_array(length, div3);
	delete_gate_bootstrapping_ciphertext_array(length, O_2);
	delete_gate_bootstrapping_ciphertext_array(length, O_3);
	delete_gate_bootstrapping_ciphertext_array(length, output);


}

///////////////////////////////     Logarithm     ////////////////////////////
// log base 2 of b
// binary logarithm

void HomBinLog(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	LweSample* power2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* power2S = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Output = new_gate_bootstrapping_ciphertext_array(length-1, bk->params);
	LweSample* int_sum = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dec_sum = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp_sum = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	//// find digit of 'b'
	// fill power2comp with zeroes
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&power2[i], 0, bk);}

	for(int i = 0; i < length; i++){
		bootsCONSTANT(&int_sum[i], 0 , bk);
		bootsCONSTANT(&dec_sum[i], 0 , bk);
		bootsCONSTANT(&temp_sum[i], 0 , bk);
	}

	for(int i = 0; i < length-2; i++){			//compare Setting with the b
		bootsCONSTANT(&power2[i], 1, bk);
		HomCompLE(&temp[0], b, power2, length, bk);		//store outcomes in Output array
		HomRShift(power2S, power2, length, 1, bk);
		HomCompS(&temp[1], b, power2S, length, bk);
		bootsAND(&Output[i], &temp[0], &temp[1], bk);
		bootsCONSTANT(&power2[i], 0, bk);
	}
	bootsCONSTANT(&power2[length-2], 1, bk);
	HomCompLE(&Output[length-2], b, power2, length, bk);

	int ll = log2(length);

	for(int i = 0; i < length-1; i++){
		HomP2C(temp_sum, i-(length/2)+1, ll+1, bk);

		for(int j = 0; j < ll+1; j++){
			bootsAND(&temp_sum[j], &temp_sum[j], &Output[i], bk);}
		HomAdd(int_sum, int_sum, temp_sum, ll+1, bk);

		if (i-(length/2)+1 < 0){
			HomRShift(res, b, length, abs(i-(length/2)+1), bk);
			for(int j = 0; j < (length/2)-1; j++){
				bootsAND(&temp_sum[j], &temp_sum[j], &Output[i], bk);}
			HomAdd(dec_sum, dec_sum, temp_sum, (length/2)-1, bk);}

		else if (i-(length/2)+1 == 0){
			for(int j = 0; j < (length/2)-1; j++){
				bootsAND(&temp_sum[j], &temp_sum[j], &Output[i], bk);}
			HomAdd(dec_sum, dec_sum, temp_sum, (length/2)-1, bk);}
						
		else {
			HomLShift(temp_sum, b, length, i-(length/2)+1, bk);
			for(int j = 0; j < (length/2)-1; j++){
				bootsAND(&temp_sum[j], &temp_sum[j], &Output[i], bk);}
			HomAdd(dec_sum, dec_sum, temp_sum, (length/2)-1, bk);}
	}

	for(int i = 0; i < (length/2)-1; i++)
		bootsCOPY(&res[i], &dec_sum[i], bk);

	for(int i = (length/2)-1; i < (length/2) + ll; i++)
		bootsCOPY(&res[i], &int_sum[i-(length/2)+1], bk);

	for(int i = (length/2) + ll; i < length; i++)
		bootsCOPY(&res[i], &int_sum[ll], bk);



	delete_gate_bootstrapping_ciphertext_array(2, temp);
	delete_gate_bootstrapping_ciphertext_array(length, power2);
	delete_gate_bootstrapping_ciphertext_array(length, power2S);
	delete_gate_bootstrapping_ciphertext_array(length-1, Output);
	delete_gate_bootstrapping_ciphertext_array(length/2, int_sum);
	delete_gate_bootstrapping_ciphertext_array(length/2, dec_sum);
	delete_gate_bootstrapping_ciphertext_array(length, temp_sum);
}


///////////////////////////////     Positive Exponential function      ////////////////////////////
// exponential 2 of b
// binary exponentiation

void HomBinExpP(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* enci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_x = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* k = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* msk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oam = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* xr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* sxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oar = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* stemp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	
	/// integer part of x : int_x
	// for(int i = 0; i < (length/2); i++){
	// 	bootsCONSTANT(&int_x[i], 0 , bk);
	// }
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_x[i-(length/2)+1], &b[i], bk);
	}

	/// decimal part of x : xr
	// for(int i = 0; i < length; i++){
	// 	bootsCONSTANT(&xr[i], 0 , bk);
	// }
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&xr[i], &b[i], bk);
	}

	/// temp, temp2
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&temp[i], 0 , bk);
		bootsCONSTANT(&temp2[i], 0 , bk);
	}

	/// k : 1 (shift)
	bootsCONSTANT(&k[0], 1, bk);
	for(int i = 1; i < (length/2); i++){
		bootsCONSTANT(&k[i], 0, bk);
	}

	///////// algorithm 1 : exponential function with integer x >=0 /////////
	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(enci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], enci, int_x, (length/2), bk);
		HomRShift(msk, k, length/2, i, bk);
		

		for(int j = 0; j < length/2; j++){
			bootsAND(&oam[j], &output[i], &msk[j], bk);
		}
		HomAdd(temp, oam, temp, length/2,bk);

		///// next to msb part /////
		HomRShift(sxr, xr, length-1, i, bk);
		
		for(int j = 0; j < length-1; j++){
			bootsAND(&oar[j], &output[i], &sxr[j], bk);
		}
		HomAdd(temp2, oar, temp2, length-2, bk);
}
	HomRShift(stemp, temp, length-1, (length/2)-1, bk);

	HomAdd(final, stemp, temp2, length, bk);
	
	for(int i = 0; i < length-2; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}


	// for(int i = (length/2)-1; i < length; i++){
	// 	bootsCOPY(&res[i], &temp[i-(length/2)+1], bk);
	// }

	// for(int i = 0; i < length-2; i++){
	// 	bootsCOPY(&res[i], &temp2[i], bk);
	// }

	delete_gate_bootstrapping_ciphertext_array(length, enci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_x);
	delete_gate_bootstrapping_ciphertext_array(length, k);
	delete_gate_bootstrapping_ciphertext_array(length, msk);
	delete_gate_bootstrapping_ciphertext_array(length, oam);
	delete_gate_bootstrapping_ciphertext_array(length, temp);
	delete_gate_bootstrapping_ciphertext_array(length, xr);
	delete_gate_bootstrapping_ciphertext_array(length, sxr);
	delete_gate_bootstrapping_ciphertext_array(length, oar);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	delete_gate_bootstrapping_ciphertext_array(length, stemp);
	delete_gate_bootstrapping_ciphertext_array(length, final);
	
}

///////////////////////////////     Negative Exponential function      ////////////////////////////
// exponential 2 of b
// binary exponentiation

void HomBinExpN(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* enci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nsk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oan = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* snxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oasr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	/// absolute value of x
	HomAbs(avx, b, length, bk);

	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_avx[i-(length/2)+1], &avx[i], bk);
	}

	/// nk : 1 (shift)
	for(int i = 0; i < (length/2)-1; i++){
		bootsCONSTANT(&nk[i], 0, bk);
	}
	bootsCONSTANT(&nk[(length/2)-1], 1, bk);
	
	/// temp3, temp4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&temp3[i], 0 , bk);
		bootsCONSTANT(&temp4[i], 0 , bk);
	}

	/// decimal part of x
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&nxr[i], &avx[i], bk);
	}

	///////// algorithm 2 : exponential function with integer x < 0 /////////

	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(enci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], enci, int_avx, (length/2), bk);
		HomLShift(nsk, nk, length/2, i, bk);
		
		for(int j = 0; j < length/2; j++){
			bootsAND(&oan[j], &output[i], &nsk[j], bk);
		}
		HomAdd(temp3, oan, temp3, length/2,bk);

		///// next to msb part /////
		HomLShift(snxr, nxr, length-1, i+1, bk);
		
		for(int j = 0; j < length-1; j++){
			bootsAND(&oasr[j], &output[i], &snxr[j], bk);
		}
		HomAdd(temp4, oasr, temp4, (length/2)-1, bk);
}
	
	HomSubt(final, temp3, temp4, length, bk);
	
	for(int i = 0; i < length; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}

	delete_gate_bootstrapping_ciphertext_array(length, avx);
	delete_gate_bootstrapping_ciphertext_array(length, enci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_avx);
	delete_gate_bootstrapping_ciphertext_array(length, nk);
	delete_gate_bootstrapping_ciphertext_array(length, nsk);
	delete_gate_bootstrapping_ciphertext_array(length, oan);
	delete_gate_bootstrapping_ciphertext_array(length, temp3);
	delete_gate_bootstrapping_ciphertext_array(length, nxr);
	delete_gate_bootstrapping_ciphertext_array(length, snxr);
	delete_gate_bootstrapping_ciphertext_array(length, oasr);
	delete_gate_bootstrapping_ciphertext_array(length, temp4);
	delete_gate_bootstrapping_ciphertext_array(length, final);
}

void HomSig(LweSample* res, const LweSample* x, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* null = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* mx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* exp_mx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* one = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dec = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* outcome = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	/////for sigmoid function, we need -x for 1/(1+exp(-x))
	////x converted to -x by 0-x
	//make 0 in a binary array
	for(int i=0;i<length;i++)
	{
		bootsCONSTANT(&null[i], 0, bk);
	}
	//0-x
	HomSubt(mx, null, x, length, bk);
	////exp(-x) using HomBinExp
	HomBinExpP(exp_mx, mx, length, bk);
	////1+exp(-x)
	//make 1 for addition
	for(int i=1;i<length;i++)
	{
		bootsCONSTANT(&one[i], 0, bk);
	}
	bootsCONSTANT(&one[0], 1, bk);
	//add 1 to exp(-x) that is one + exp_mx and store it in dec
	HomAdd(dec, one, exp_mx, length, bk);
	////Division of dec by 1 is our result 
	//remainder not needed : A
	HomDiv(outcome, A, one, dec, length, bk);
	//copy updated result of outcome to res
	for(int i=0;i<length;i++)
	{
		bootsCOPY(&res[i], &outcome[i], bk);	
	}

	delete_gate_bootstrapping_ciphertext_array(length, null);
	delete_gate_bootstrapping_ciphertext_array(length, mx);
	delete_gate_bootstrapping_ciphertext_array(length, exp_mx);
	delete_gate_bootstrapping_ciphertext_array(length, one);
	delete_gate_bootstrapping_ciphertext_array(length, dec);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(length, outcome);

}

///////////////////////////////     Positive Exponential function ver.2(revised)      ////////////////////////////
// exponential 2 of b
// binary exponentiation

void HomBinExpPv2(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* enci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_x = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* k = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* msk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oam = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* xr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* sxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oar = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* stemp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	
	/// 1) integer part of x : int_x
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_x[i-(length/2)+1], &b[i], bk);
	}

	/// 2) decimal part of x : xr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&xr[i], &b[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&xr[i], 0, bk);
	}

	/// temp, temp2
	for(int i = 0; i < length/2; i++){
		bootsCONSTANT(&temp[i], 0 , bk);
		bootsCONSTANT(&temp2[i], 0 , bk);
	}

	/// 3) k : 1 (shift) [00010000]
	bootsCONSTANT(&k[0], 1, bk);
	for(int i = 1; i < (length/2); i++){
		bootsCONSTANT(&k[i], 0, bk);
	}
	// for(int i = 0; i < (length/2)-1; i++){
	// 	bootsCONSTANT(&k[i], 0, bk);
	// }
	// bootsCONSTANT(&k[(length/2)-1], 1, bk);
	// for(int i = length/2; i < length; i++){
	// 	bootsCONSTANT(&k[i], 0, bk);
	// }

	///////// algorithm 1 : exponential function with integer x >=0 /////////
	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(enci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], enci, int_x, (length/2), bk);
		HomRShift(msk, k, length/2, i, bk);
		

		for(int j = 0; j < length/2; j++){
			bootsAND(&oam[j], &output[i], &msk[j], bk);
		}
		HomAdd(temp, oam, temp, length/2,bk);

		///// next to msb part /////
		HomRShift(sxr, xr, length, i, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oar[j], &output[i], &sxr[j], bk);
		}
		HomAdd(temp2, oar, temp2, length, bk);
}
	HomRShift(stemp, temp, length, (length/2)-1, bk);

	HomAdd(final, stemp, temp2, length, bk);
	
	for(int i = 0; i < length-2; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}


	// for(int i = (length/2)-1; i < length; i++){
	// 	bootsCOPY(&res[i], &temp[i-(length/2)+1], bk);
	// }

	// for(int i = 0; i < length-2; i++){
	// 	bootsCOPY(&res[i], &temp2[i], bk);
	// }

	delete_gate_bootstrapping_ciphertext_array(length, enci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_x);
	delete_gate_bootstrapping_ciphertext_array(length, k);
	delete_gate_bootstrapping_ciphertext_array(length, msk);
	delete_gate_bootstrapping_ciphertext_array(length, oam);
	delete_gate_bootstrapping_ciphertext_array(length, temp);
	delete_gate_bootstrapping_ciphertext_array(length, xr);
	delete_gate_bootstrapping_ciphertext_array(length, sxr);
	delete_gate_bootstrapping_ciphertext_array(length, oar);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	delete_gate_bootstrapping_ciphertext_array(length, stemp);
	delete_gate_bootstrapping_ciphertext_array(length, final);
	
}

///////////////////////////////     Negative Exponential function ver.2     ////////////////////////////
// exponential 2 of b
// binary exponentiation

void HomBinExpNv2(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nenci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nsk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oan = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* snxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oasr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	/// absolute value of x
	HomAbs(avx, b, length, bk);

	/// 1) integer part of abs(x) : int_avx
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_avx[i-(length/2)+1], &avx[i], bk);
	}
	/// 2) decimal part of avx : nxr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&nxr[i], &avx[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&nxr[i], 0, bk);
	}
	/// temp3, temp4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&temp3[i], 0 , bk);
		bootsCONSTANT(&temp4[i], 0 , bk);
	}
	/// 3) nk : 1 (shift)
	for(int i = 0; i < (length/2)-1; i++){
		bootsCONSTANT(&nk[i], 0, bk);
	}
	bootsCONSTANT(&nk[(length/2)-1], 1, bk);

	///////// algorithm 2 : exponential function with integer x < 0 /////////

	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(nenci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], nenci, int_avx, (length/2), bk);
		HomLShift(nsk, nk, length/2, i, bk);
		
		for(int j = 0; j < length/2; j++){
			bootsAND(&oan[j], &output[i], &nsk[j], bk);
		}
		HomAdd(temp3, oan, temp3, length/2,bk);

		///// next to msb part /////
		HomLShift(snxr, nxr, length, i+1, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oasr[j], &output[i], &snxr[j], bk);
		}
		HomAdd(temp4, oasr, temp4, length, bk);
}

	HomSubt(final, temp3, temp4, length, bk);
	
	for(int i = 0; i < length; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}

	delete_gate_bootstrapping_ciphertext_array(length, avx);
	delete_gate_bootstrapping_ciphertext_array(length, nenci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_avx);
	delete_gate_bootstrapping_ciphertext_array(length, nk);
	delete_gate_bootstrapping_ciphertext_array(length, nsk);
	delete_gate_bootstrapping_ciphertext_array(length, oan);
	delete_gate_bootstrapping_ciphertext_array(length, temp3);
	delete_gate_bootstrapping_ciphertext_array(length, nxr);
	delete_gate_bootstrapping_ciphertext_array(length, snxr);
	delete_gate_bootstrapping_ciphertext_array(length, oasr);
	delete_gate_bootstrapping_ciphertext_array(length, temp4);
	delete_gate_bootstrapping_ciphertext_array(length, final);
}

///////////////////////////////     Final Exponential function      ////////////////////////////
// exponential 2 of b
// binary exponentiation(positive + negative)

void HomBinExpFinal(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){
	//positive ciphertext array
	LweSample* enci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_x = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* k = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* msk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oam = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* xr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* sxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oar = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* stemp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final_pos = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//negative ciphertext array
	LweSample* avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nenci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* noutput = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nsk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oan = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* snxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oasr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final_neg = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//~x[signed bit] (AND) A + x[signed bit]
	LweSample* nb = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	//////////        Positive Exponentiation        //////////
	/// 1) integer part of x : int_x
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_x[i-(length/2)+1], &b[i], bk);
	}

	/// 2) decimal part of x : xr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&xr[i], &b[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&xr[i], 0, bk);
	}

	/// temp, temp2
	for(int i = 0; i < length/2; i++){
		bootsCONSTANT(&temp[i], 0 , bk);
		bootsCONSTANT(&temp2[i], 0 , bk);
	}

	/// 3) k : 1 (shift) [00010000]
	bootsCONSTANT(&k[0], 1, bk);
	for(int i = 1; i < (length/2); i++){
		bootsCONSTANT(&k[i], 0, bk);
	}

	///////// algorithm 1 : exponential function with integer x >=0 /////////
	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(enci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], enci, int_x, (length/2), bk);
		HomRShift(msk, k, length/2, i, bk);
		

		for(int j = 0; j < length/2; j++){
			bootsAND(&oam[j], &output[i], &msk[j], bk);
		}
		HomAdd(temp, oam, temp, length/2,bk);

		///// next to msb part /////
		HomRShift(sxr, xr, length, i, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oar[j], &output[i], &sxr[j], bk);
		}
		HomAdd(temp2, oar, temp2, length, bk);
}
	HomRShift(stemp, temp, length, (length/2)-1, bk);

	HomAdd(final_pos, stemp, temp2, length, bk);

	//////////        Negative Exponentiation        //////////
	/// absolute value of x
	HomAbs(avx, b, length, bk);

	/// 1) integer part of abs(x) : int_avx
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_avx[i-(length/2)+1], &avx[i], bk);
	}
	/// 2) decimal part of avx : nxr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&nxr[i], &avx[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&nxr[i], 0, bk);
	}
	/// temp3, temp4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&temp3[i], 0 , bk);
		bootsCONSTANT(&temp4[i], 0 , bk);
	}
	/// 3) nk : 1 (shift)
	for(int i = 0; i < (length/2)-1; i++){
		bootsCONSTANT(&nk[i], 0, bk);
	}
	bootsCONSTANT(&nk[(length/2)-1], 1, bk);

	///////// algorithm 2 : exponential function with integer x < 0 /////////

	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(nenci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&noutput[i], nenci, int_avx, (length/2), bk);
		HomLShift(nsk, nk, length/2, i, bk);
		
		for(int j = 0; j < length/2; j++){
			bootsAND(&oan[j], &noutput[i], &nsk[j], bk);
		}
		HomAdd(temp3, oan, temp3, length/2,bk);

		///// next to msb part /////
		HomLShift(snxr, nxr, length, i+1, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oasr[j], &noutput[i], &snxr[j], bk);
		}
		HomAdd(temp4, oasr, temp4, length, bk);
}

	HomSubt(final_neg, temp3, temp4, length, bk);
	
	//////////        Selective Integration        //////////
	///// ~x[signed bit] (AND) A + x[signed bit] (AND) B :: A = positive alg. outcome, B = negative alg. outcome
	//~x (AND) A : positive
	bootsNOT(&nb[0], &b[length-1], bk);
	for(int i = 0; i < length; i++){
		bootsAND(&final_pos[i], &nb[0], &final_pos[i], bk);
	}	
	//x (AND) B : negative
	for(int i = 0; i < length; i++){
		bootsAND(&final_neg[i], &b[length-1], &final_neg[i], bk);
	}	
	// ~x[signed bit] (AND) A + x[signed bit]
	HomAdd(final, final_pos, final_neg, length, bk);	
	//copy final to result
	for(int i = 0; i < length; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}

	//positive ciphertext array : delete
	delete_gate_bootstrapping_ciphertext_array(length, enci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_x);
	delete_gate_bootstrapping_ciphertext_array(length, k);
	delete_gate_bootstrapping_ciphertext_array(length, msk);
	delete_gate_bootstrapping_ciphertext_array(length, oam);
	delete_gate_bootstrapping_ciphertext_array(length, temp);
	delete_gate_bootstrapping_ciphertext_array(length, xr);
	delete_gate_bootstrapping_ciphertext_array(length, sxr);
	delete_gate_bootstrapping_ciphertext_array(length, oar);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	delete_gate_bootstrapping_ciphertext_array(length, stemp);
	delete_gate_bootstrapping_ciphertext_array(length, final_pos);	
	//negative ciphertext array : delete
	delete_gate_bootstrapping_ciphertext_array(length, avx);
	delete_gate_bootstrapping_ciphertext_array(length, nenci);
	delete_gate_bootstrapping_ciphertext_array(length, noutput);
	delete_gate_bootstrapping_ciphertext_array(length, int_avx);
	delete_gate_bootstrapping_ciphertext_array(length, nk);
	delete_gate_bootstrapping_ciphertext_array(length, nsk);
	delete_gate_bootstrapping_ciphertext_array(length, oan);
	delete_gate_bootstrapping_ciphertext_array(length, temp3);
	delete_gate_bootstrapping_ciphertext_array(length, nxr);
	delete_gate_bootstrapping_ciphertext_array(length, snxr);
	delete_gate_bootstrapping_ciphertext_array(length, oasr);
	delete_gate_bootstrapping_ciphertext_array(length, temp4);
	delete_gate_bootstrapping_ciphertext_array(length, final_neg);
	//~x[signed bit] (AND) A + x[signed bit]
	delete_gate_bootstrapping_ciphertext_array(1, nb);
	delete_gate_bootstrapping_ciphertext_array(length, final);
}

///////////////////////////////     Exponential function base 'e'      ////////////////////////////
// exponential e of b

void HomeExp(LweSample* res, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){
	//preprocessing
	LweSample* pre = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* ni = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//positive ciphertext array
	LweSample* enci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* output = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_x = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* k = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* msk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oam = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* xr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* sxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oar = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* stemp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final_pos = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//negative ciphertext array
	LweSample* avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nenci = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* noutput = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* int_avx = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nsk = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oan = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* nxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* snxr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* oasr = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* final_neg = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//~x[signed bit] (AND) A + x[signed bit]
	LweSample* nb = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* final = new_gate_bootstrapping_ciphertext_array(length, bk->params);


	//////////       1. Preprocessing        //////////
	///// use log2(e) * b as an input
	/// 1) build up log2(e)=110.10000 when 8 bit
	/// for ref : log2(e)=1.01110001010101001101 binary
	for(int i = 0; i < 2; i++){
		bootsCONSTANT(&pre[i], 1, bk);
	}
	bootsCONSTANT(&pre[2], 0, bk);
	bootsCONSTANT(&pre[3], 1, bk);
	for(int i = 4; i < length; i++){
		bootsCONSTANT(&pre[i], 0, bk);
	}	
	/// 2) new_input(ni) = log2(e)*b = pre (MULT) b 
	HomMulti(ni, pre, b, length, bk);
	

	//////////       2. Positive Exponentiation        //////////
	/// 1) integer part of x : int_x
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_x[i-(length/2)+1], &ni[i], bk);
	}
	/// 2) decimal part of x : xr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&xr[i], &ni[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&xr[i], 0, bk);
	}
	/// temp, temp2
	for(int i = 0; i < length/2; i++){
		bootsCONSTANT(&temp[i], 0 , bk);
		bootsCONSTANT(&temp2[i], 0 , bk);
	}
	/// 3) k : 1 (shift) [00010000]
	bootsCONSTANT(&k[0], 1, bk);
	for(int i = 1; i < (length/2); i++){
		bootsCONSTANT(&k[i], 0, bk);
	}

	///////// algorithm 1 : exponential function with integer x >=0 /////////
	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(enci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&output[i], enci, int_x, (length/2), bk);
		HomRShift(msk, k, length/2, i, bk);
		

		for(int j = 0; j < length/2; j++){
			bootsAND(&oam[j], &output[i], &msk[j], bk);
		}
		HomAdd(temp, oam, temp, length/2,bk);

		///// next to msb part /////
		HomRShift(sxr, xr, length, i, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oar[j], &output[i], &sxr[j], bk);
		}
		HomAdd(temp2, oar, temp2, length, bk);
}
	HomRShift(stemp, temp, length, (length/2)-1, bk);

	HomAdd(final_pos, stemp, temp2, length, bk);

	//////////       3. Negative Exponentiation        //////////
	/// absolute value of x
	HomAbs(avx, ni, length, bk);

	/// 1) integer part of abs(x) : int_avx
	for(int i = (length/2)-1; i < length-1; i++){
		bootsCOPY(&int_avx[i-(length/2)+1], &avx[i], bk);
	}
	/// 2) decimal part of avx : nxr
	for(int i = 0; i < (length/2)-1; i++){
		bootsCOPY(&nxr[i], &avx[i], bk);
	}
	for(int i = (length/2)-1; i < length; i++){
		bootsCONSTANT(&nxr[i], 0, bk);
	}
	/// temp3, temp4
	for(int i = 0; i < length; i++){
		bootsCONSTANT(&temp3[i], 0 , bk);
		bootsCONSTANT(&temp4[i], 0 , bk);
	}
	/// 3) nk : 1 (shift)
	for(int i = 0; i < (length/2)-1; i++){
		bootsCONSTANT(&nk[i], 0, bk);
	}
	bootsCONSTANT(&nk[(length/2)-1], 1, bk);

	///////// algorithm 2 : exponential function with integer x < 0 /////////

	for(int i = 0; i < (length/2); i++){
		///// E[i] /////		
		HomP2C(nenci, i, (length/2), bk);

		///// msb part /////
		HomEqui(&noutput[i], nenci, int_avx, (length/2), bk);
		HomLShift(nsk, nk, length/2, i, bk);
		
		for(int j = 0; j < length/2; j++){
			bootsAND(&oan[j], &noutput[i], &nsk[j], bk);
		}
		HomAdd(temp3, oan, temp3, length/2,bk);

		///// next to msb part /////
		HomLShift(snxr, nxr, length, i+1, bk);
		
		for(int j = 0; j < length; j++){
			bootsAND(&oasr[j], &noutput[i], &snxr[j], bk);
		}
		HomAdd(temp4, oasr, temp4, length, bk);
}

	HomSubt(final_neg, temp3, temp4, length, bk);
	
	//////////       4. Selective Integration        //////////
	///// ~x[signed bit] (AND) A + x[signed bit] (AND) B :: A = positive alg. outcome, B = negative alg. outcome
	//~ni (AND) A : positive
	bootsNOT(&nb[0], &ni[length-1], bk);
	for(int i = 0; i < length; i++){
		bootsAND(&final_pos[i], &nb[0], &final_pos[i], bk);
	}	
	//x (AND) B : negative
	for(int i = 0; i < length; i++){
		bootsAND(&final_neg[i], &ni[length-1], &final_neg[i], bk);
	}	
	// ~x[signed bit] (AND) A + x[signed bit]
	HomAdd(final, final_pos, final_neg, length, bk);	
	//copy final to result
	for(int i = 0; i < length; i++){
		bootsCOPY(&res[i], &final[i], bk);
	}

	//preprocessing
	delete_gate_bootstrapping_ciphertext_array(length, pre);
	delete_gate_bootstrapping_ciphertext_array(length, ni);
	//positive ciphertext array : delete
	delete_gate_bootstrapping_ciphertext_array(length, enci);
	delete_gate_bootstrapping_ciphertext_array(length, output);
	delete_gate_bootstrapping_ciphertext_array(length, int_x);
	delete_gate_bootstrapping_ciphertext_array(length, k);
	delete_gate_bootstrapping_ciphertext_array(length, msk);
	delete_gate_bootstrapping_ciphertext_array(length, oam);
	delete_gate_bootstrapping_ciphertext_array(length, temp);
	delete_gate_bootstrapping_ciphertext_array(length, xr);
	delete_gate_bootstrapping_ciphertext_array(length, sxr);
	delete_gate_bootstrapping_ciphertext_array(length, oar);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	delete_gate_bootstrapping_ciphertext_array(length, stemp);
	delete_gate_bootstrapping_ciphertext_array(length, final_pos);	
	//negative ciphertext array : delete
	delete_gate_bootstrapping_ciphertext_array(length, avx);
	delete_gate_bootstrapping_ciphertext_array(length, nenci);
	delete_gate_bootstrapping_ciphertext_array(length, noutput);
	delete_gate_bootstrapping_ciphertext_array(length, int_avx);
	delete_gate_bootstrapping_ciphertext_array(length, nk);
	delete_gate_bootstrapping_ciphertext_array(length, nsk);
	delete_gate_bootstrapping_ciphertext_array(length, oan);
	delete_gate_bootstrapping_ciphertext_array(length, temp3);
	delete_gate_bootstrapping_ciphertext_array(length, nxr);
	delete_gate_bootstrapping_ciphertext_array(length, snxr);
	delete_gate_bootstrapping_ciphertext_array(length, oasr);
	delete_gate_bootstrapping_ciphertext_array(length, temp4);
	delete_gate_bootstrapping_ciphertext_array(length, final_neg);
	//~x[signed bit] (AND) A + x[signed bit]
	delete_gate_bootstrapping_ciphertext_array(1, nb);
	delete_gate_bootstrapping_ciphertext_array(length, final);
}

///////////////////////////////     Sigmoid: binary 2020 version     ////////////////////////////
//res = 1 + exp(-x)
//input is binary ciphertext with length l

void HomSigBin(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	// 1. b <- -a
	LweSample* b = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomTwosCompliment(b, a, length, bk);
	// 2. b <- exp(b): this will make exp(-x)
	HomeExp(b, b, length, bk);

	// 3. add 1
	// 1) make one in real binary
	LweSample* one = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	// 000 0000 0
	for(int i=0; i< length; i++)
		bootsCONSTANT(&one[i], 0, bk);
	// 000 1000 0
	bootsCONSTANT(&one[(length/2)-1], 1, bk);	
	// 2) add by 1: a <- a + one
	HomAdd(b, b, one, length, bk);

	// 4. divide: b <- 1 / b
	// to use HomDiv, need res1(quotient)and res2(remainder); we don't need remainder but for the function
	// res1 will be a and res will be junk
	LweSample* remainder = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	// a <- one / a
	HomDiv(b, remainder, one, b, length, bk);

	// 5. paste the result: this is our encrypted result
	for(int i=0; i< length; i++)
		bootsCOPY(&res[i], &b[i], bk);

	// delete all pointers
	delete_gate_bootstrapping_ciphertext_array(length, b);
	delete_gate_bootstrapping_ciphertext_array(length, one);
	delete_gate_bootstrapping_ciphertext_array(length, remainder);

}

///////////////////////////////     Sigmoid Der: binary 2020 version     ////////////////////////////
// input: a <- Sig
// calculate sigmoid derivative = Sig(1-Sig) from calculated sigmoid value Sig
// 1 Subt and 1 Mult

void HomSigBinDer(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	// 1. we need one
	LweSample* one = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	// 000 0000 0
	for(int i=0; i< length; i++)
		bootsCONSTANT(&one[i], 0, bk);
	// 000 1000 0
	bootsCONSTANT(&one[(length/2)-1], 1, bk);

	// 2. b <- subtract 1 by a
	LweSample* b = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomSubt(b, one, a, length, bk);

	// 3. b <- a * b = Sig * (1 - Sig)
	HomMultiReal(b, a, b, length, bk);

	// 4. return b as our derivative for the sigmoid function
	for(int i=0; i< length; i++)
		bootsCOPY(&res[i], &b[i], bk);

	// delete all pointers
	delete_gate_bootstrapping_ciphertext_array(length, b);
	delete_gate_bootstrapping_ciphertext_array(length, one);

}

///////////////////////////////     Multilayer Perceptron NN     ////////////////////////////
// ---- params ----
// layer_num = 3
// network [1,1,1]
// EPOCH = 1
// learning_rate = 0.25 = 010 0000 0 = but instead of multiplication, we can use left shift 2 times

// ---- process ----
// A. FEEDFORWARD
// <1> 1) z2 = w2 * a + b2    2) a2 = S(z2) 
// <2> 1) z3 = w3 * a2 + b3   2) a3 = S(z3)

// B. BACKPROPAGATION
// input: first consider one input
// EX: (a, b): b is a label
// follow update rule: partial derivatives
// use HomSigBinDer function for sigmoid derivative
// need 6 params for gradients: dC_da3, dC_db3, dC_dw3, dC_da2, dC_db2, dCdw2
// update by subtraction of LR * gradients

// res: return a3, but the goal is updating parameter

void HomMLPNN(LweSample* res, const LweSample *a, const LweSample *b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	// FHE Multilayer Perceptron Neural Network

	// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	// ::::::::::::::::::::::: FEEDFORWARD :::::::::::::::::::::::
	// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	// 1. we need weights; initialize it to 0.5 for all w's and b's
	LweSample* w2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* w3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* b2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* b3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	// 0.5 in real binary is 001 0000 0
	for (int i=0; i<length; i++){
		bootsCONSTANT(&w2[i], 0, bk);
		bootsCONSTANT(&w3[i], 0, bk);
		bootsCONSTANT(&b2[i], 0, bk);
		bootsCONSTANT(&b3[i], 0, bk);
	}
	bootsCONSTANT(&w2[(length/2)-2], 1, bk);
	bootsCONSTANT(&w3[(length/2)-2], 1, bk);
	bootsCONSTANT(&b2[(length/2)-2], 1, bk);
	bootsCONSTANT(&b3[(length/2)-2], 1, bk);

	// ::::::::::::::::::::::: LOOP STARTS :::::::::::::::::::::::

	// EPOCH: 1
	// LAYER 1-2
	// 2R. z2 = w2 * a + b2
	// make z2
	LweSample* z2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomMultiReal(z2, w2, a, length, bk);
	HomAdd(z2, z2, b2, length, bk);

	// 3R. a2 = S(z2)
	LweSample* a2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomSigBin(a2, z2, length, bk);

	// LAYER 2-3
	// repeat step 2 & 3
	// 2R. z3 = w3 * a2 + b3
	// make z3
	LweSample* z3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomMultiReal(z3, w3, a2, length, bk);
	HomAdd(z3, z3, b3, length, bk);

	// 3R. a3 = S(z3)
	LweSample* a3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomSigBin(a3, z3, length, bk);

	// ::::::::::::::::::::::: LOOP ENDS :::::::::::::::::::::::
	
	// this is just dummy:: later it will be used for prediction
	// our predition
	for(int i=0; i< length; i++)
		bootsCOPY(&res[i], &a3[i], bk);

	// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	// ::::::::::::::::::::: BACKPROPAGATION :::::::::::::::::::::
	// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	
	// 1. need 6 params for gradients: dC_da3, dC_db3, dC_dw3, dC_da2, dC_db2, dCdw2
	LweSample* dC_da3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dC_db3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dC_dw3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dC_da2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dC_db2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* dC_dw2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	// + we need derivative of sigmoid: calculate sigmoid derivatives of z3 and z2 and save it in z3 and z2, respectively
	HomSigBinDer(z3, z3, length, bk);
	HomSigBinDer(z2, z2, length, bk);

	// ::::::::::::::::::::::: LOOP STARTS :::::::::::::::::::::::

	// 2. first backpropagation
	// dC_da3 = a3 - b  
	HomSubt(dC_da3, a3, b, length, bk);
	// dC_db3 = dC_da3 * z3
	HomMultiReal(dC_db3, dC_da3, z3, length, bk);
	// dC_dw3 = dC_db3 * a2
	HomMultiReal(dC_dw3, dC_db3, a2, length, bk);

	// 3. second backpropagation
	// dC_da2 = dCdb3 * w3
	HomMultiReal(dC_da2, dC_db3, w3, length, bk);	
	// dC_db2 = dC_da2 * z2
	HomMultiReal(dC_db2, dC_da2, z2, length, bk);	
	// dC_dw2 = dC_db3 * a
	HomMultiReal(dC_dw2, dC_db3, a, length, bk);	

	// ::::::::::::::::::::::: LOOP ENDS :::::::::::::::::::::::

	// 4. update: 0.25 = LEFTSHIFT 2 times
	// LR * grad's = shift 2 times of dC_db3, dC_dw3, dC_db2, dCdw2
	HomLShift(dC_db3, dC_db3, length, 2, bk);
	HomLShift(dC_dw3, dC_dw3, length, 2, bk);
	HomLShift(dC_db2, dC_db2, length, 2, bk);
	HomLShift(dC_dw2, dC_dw2, length, 2, bk);
	// update by subtracting
	HomSubt(b3, b3, dC_db3, length, bk);
	HomSubt(w3, w3, dC_dw3, length, bk);
	HomSubt(b2, b2, dC_db2, length, bk);
	HomSubt(w2, w2, dC_dw2, length, bk);

	// delete pointers
	// feedforward pointers
	delete_gate_bootstrapping_ciphertext_array(length, w2);
	delete_gate_bootstrapping_ciphertext_array(length, w3);
	delete_gate_bootstrapping_ciphertext_array(length, b2);
	delete_gate_bootstrapping_ciphertext_array(length, b3);
	delete_gate_bootstrapping_ciphertext_array(length, z2);
	delete_gate_bootstrapping_ciphertext_array(length, a2);
	delete_gate_bootstrapping_ciphertext_array(length, z3);
	delete_gate_bootstrapping_ciphertext_array(length, a3);
	
	// backpropagation pointers: dC_da3, dC_db3, dC_dw3, dC_da2, dC_db2, dCdw2
	delete_gate_bootstrapping_ciphertext_array(length, dC_da3);
	delete_gate_bootstrapping_ciphertext_array(length, dC_db3);
	delete_gate_bootstrapping_ciphertext_array(length, dC_dw3);	
	delete_gate_bootstrapping_ciphertext_array(length, dC_da2);
	delete_gate_bootstrapping_ciphertext_array(length, dC_db2);
	delete_gate_bootstrapping_ciphertext_array(length, dC_dw2);
}
