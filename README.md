# xMKCKKS
Multi‐key homomorphic encryption based on MKCKKS
HEAAN is a software library that implements homomorphic encryption (HE) that supports fixed point arithmetics. This library supports approximate operations between rational numbers. The approximate error depends on some parameters and almost same with floating point operation errors. \
This scheme is based on MKCKKS HEAAN (https://eprint.iacr.org/2018/153.pdf) and (https://github.com/snucrypto/HEAAN). The data is encrypted via an aggregated public key. For decryption, collaboration between all participating devices is required to prevent privacy leakage from publicly shared information. 

# To install the library, you need to locate the "lib" folder in the console and type:

make clean\
make all

# To build the "run-file" code, you need to locate the "run" folder and type:

make clean\
make

# To run this library, you need to type:

./TestHEAAN Encrypt 1 1

You can choose other operations from the following list : Encrypt, EncryptSingle, Add, Mult, iMult, RotateFast, Conjugate, DecryptSingle

# Dependencies

CMake (>= 3.12), GNU G++ (>= 6.0) or Clang++ (>= 5.0) (https://cmake.org/install/) \
GMP (>=6.1.2) (https://gmplib.org/) \
NTL (>=11.4.3) (https://libntl.org/)

# Licence

Copyright (c) by CryptoLab inc. This program is licensed under a Creative Commons Attribution-NonCommercial 3.0 Unported License. You should have received a copy of the license along with this work. If not, see http://creativecommons.org/licenses/by-nc/3.0/.


# Citation

Ma, J, Naas, S-A, Sigg, S, Lyu, X. Privacy-preserving federated learning based on multi-key homomorphic encryption. Int J Intell Syst. 2022; 1- 22. doi:10.1002/int.22818
