# xMKCKKS
Multi‐key homomorphic encryption based on MKCKKS
HEAAN is a software library that implements homomorphic encryption (HE) that supports fixed point arithmetics. This library supports approximate operations between rational numbers. The approximate error depends on some parameters and almost same with floating point operation errors. In this scheme, data is encrypted via an aggregated public key before sharing with a server for aggregation. For decryption, collaboration between all participating devices is required to prevent privacy leakage from publicly shared information. 

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

@article{eXtendedMKCKKS,
  author    = {Jing Ma and
               Si{-}Ahmed Naas and
               Stephan Sigg and
               Xixiang Lyu},
  title     = {Privacy-preserving Federated Learning based on Multi-key Homomorphic
               Encryption},
  journal   = {CoRR},
  volume    = {abs/2104.06824},
  year      = {2021},
  url       = {https://arxiv.org/abs/2104.06824},
  eprinttype = {arXiv},
  eprint    = {2104.06824},
  timestamp = {Mon, 19 Apr 2021 16:45:47 +0200},
  biburl    = {https://dblp.org/rec/journals/corr/abs-2104-06824.bib},
  bibsource = {dblp computer science bibliography, https://dblp.org}
}
