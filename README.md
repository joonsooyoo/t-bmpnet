# t-bmpnet

t-BMPNet: trainable Bitwise Multilayer Perceptron Neural Network over Fully Homomomorphic Encryption scheme

BMPNet uses TFHE library: https://tfhe.github.io/tfhe/
(For the environment setting, go to the URL above and download the latest version.)

Experiment Folder (t-BMPNet and Other Approaches)
1. FHE_Feedforward: contains Feedforward Neural Network using Boolean Gates
2. FHE_trainable_BMPNet: contains trainable Bitwise Neural Network using Boolean Gates (in our words, t-BMPNet)
3. bfv_feedforward: contains Feedforward Neural Network using BFV scheme
4. ckks_feedforward: contains Feedforward Neural Network using CKKS scheme (activation function: square and sigmoid)

Note that we use SEAL library to test BFV and CKKS scheme for the leveled version.
The library can be downloaded at https://github.com/microsoft/SEAL

For more information, contact sandiegojs@korea.ac.kr
