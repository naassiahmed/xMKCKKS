# xMKCKKS
Multi‐key homomorphic encryption based on MKCKKS
HEAAN is a software library that implements homomorphic encryption (HE) that supports fixed point arithmetics. This library supports approximate operations between rational numbers. The approximate error depends on some parameters and almost same with floating point operation errors.

# To install the library, you need to locate the "lib" folder in the console and type:

make clean\
make all

# To build the "run-file" code, you need to locate the "run" folder and type:

make clean\
make

# To run this library, you need to type:

./TestHEAAN Encrypt 1 1

You can choose other operations from the following list : Encrypt, EncryptSingle, Add, Mult, iMult, RotateFast, Conjugate, DecryptSingle

# Licence

Copyright (c) by CryptoLab inc. This program is licensed under a Creative Commons Attribution-NonCommercial 3.0 Unported License. You should have received a copy of the license along with this work. If not, see http://creativecommons.org/licenses/by-nc/3.0/.
