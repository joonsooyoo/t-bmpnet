#include "helper_func.h"
#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;
using namespace seal;

#include "ckks_nn_sigmoid.h"
#include "ckks_nn_square.h"


int main(){

	/********** test **********/

	ckks_nn_sigmoid();
	// ckks_nn_square();
	
	return 0;
}
