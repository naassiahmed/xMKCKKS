/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "TestScheme.h"
#include <stdio.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>

#include "Ciphertext.h"
#include "EvaluatorUtils.h"
#include "Ring.h"
#include "Scheme.h"
#include "SchemeAlgo.h"
#include "SecretKey.h"
#include "StringUtils.h"
#include "TimeUtils.h"
#include "SerializationUtils.h"
#include <chrono>
#include <time.h>

using namespace std;
using namespace NTL;


//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------

void TestScheme::Benchmark(long logq, long logp, long logn,int batch) {
	
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_end);
	time_task=(float)(((ts_end.tv_sec - ts_beg.tv_sec) + (ts_end.tv_nsec - ts_beg.tv_nsec) / 1e9)*1000);
	timeutils.stop("----");
	outfile << time_task << endl;






	
}

void TestScheme::SimpleEncryptMsg(Ciphertext& cipher, Plaintext& plain,SecretKey& EncKey,Ciphertext& cipher1, Plaintext& plain1,SecretKey& EncKey1,Ciphertext& cipher2, Plaintext& plain2,SecretKey& EncKey2,Ciphertext& cipher3, Plaintext& plain3,SecretKey& EncKey3,Ciphertext& cipher4, Plaintext& plain4,SecretKey& EncKey4,Ciphertext& cipher5, Plaintext& plain5,SecretKey& EncKey5,Ciphertext& cipher6, Plaintext& plain6,SecretKey& EncKey6,Ciphertext& cipher7, Plaintext& plain7,SecretKey& EncKey7,Ciphertext& cipher8, Plaintext& plain8,SecretKey& EncKey8,Ciphertext& cipher9, Plaintext& plain9,SecretKey& EncKey9) {
	//TimeUtils timeutils;
	//Party0	
	Ring ring;
	cipher.logp = plain.logp;
	cipher.logq = plain.logq;
	cipher.n = plain.n;
	ZZ qQ = ring.qpows[plain.logq + logQ];
	ZZ* vx = new ZZ[N];
	ring.sampleZO(vx);	
	//timeutils.start("pk_generation");
	ZZ* axP = new ZZ[N];
	ZZ* bxP = new ZZ[N];
	long npP = ceil((1 + logQQ + logN + 2)/(double)pbnd);
	ring.sampleUniform2(axP, logQQ);
	ring.mult(bxP, EncKey.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP, QQ);
	Key* key = new Key();
	ring.CRT(key->rax, axP, nprimes);
	ring.CRT(key->rbx, bxP, nprimes);
	//timeutils.stop("pk_generation");
	

	
	//Party1
	cipher1.logp = plain1.logp;
	cipher1.logq = plain1.logq;
	cipher1.n = plain1.n;
	ZZ* bxP1 = new ZZ[N];
	ring.mult(bxP1, EncKey1.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP1, QQ);
	Key* key1 = new Key();
	ring.CRT(key1->rax, axP, nprimes);
	ring.CRT(key1->rbx, bxP1, nprimes);
	
	//Party2
	cipher2.logp = plain2.logp;
	cipher2.logq = plain2.logq;
	cipher2.n = plain2.n;
	ZZ* bxP2 = new ZZ[N];
	ring.mult(bxP2, EncKey2.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP2, QQ);
	Key* key2 = new Key();
	ring.CRT(key2->rax, axP, nprimes);
	ring.CRT(key2->rbx, bxP2, nprimes);

	//Party3
	cipher3.logp = plain3.logp;
	cipher3.logq = plain3.logq;
	cipher3.n = plain3.n;
	ZZ* bxP3 = new ZZ[N];
	ring.mult(bxP3, EncKey3.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP3, QQ);
	Key* key3 = new Key();
	ring.CRT(key3->rax, axP, nprimes);
	ring.CRT(key3->rbx, bxP3, nprimes);


	//Party4
	cipher4.logp = plain4.logp;
	cipher4.logq = plain4.logq;
	cipher4.n = plain4.n;
	ZZ* bxP4 = new ZZ[N];
	ring.mult(bxP4, EncKey4.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP4, QQ);
	Key* key4 = new Key();
	ring.CRT(key4->rax, axP, nprimes);
	ring.CRT(key4->rbx, bxP4, nprimes);


	//Party5
	cipher5.logp = plain5.logp;
	cipher5.logq = plain5.logq;
	cipher5.n = plain5.n;
	ZZ* bxP5 = new ZZ[N];
	ring.mult(bxP5, EncKey5.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP5, QQ);
	Key* key5 = new Key();
	ring.CRT(key5->rax, axP, nprimes);
	ring.CRT(key5->rbx, bxP5, nprimes);

	//Party6
	cipher6.logp = plain6.logp;
	cipher6.logq = plain6.logq;
	cipher6.n = plain6.n;
	ZZ* bxP6 = new ZZ[N];
	ring.mult(bxP6, EncKey6.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP6, QQ);
	Key* key6 = new Key();
	ring.CRT(key6->rax, axP, nprimes);
	ring.CRT(key6->rbx, bxP6, nprimes);


	//Party7
	cipher7.logp = plain7.logp;
	cipher7.logq = plain7.logq;
	cipher7.n = plain7.n;
	ZZ* bxP7 = new ZZ[N];
	ring.mult(bxP7, EncKey7.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP7, QQ);
	Key* key7 = new Key();
	ring.CRT(key7->rax, axP, nprimes);
	ring.CRT(key7->rbx, bxP7, nprimes);


	//Party8
	cipher8.logp = plain8.logp;
	cipher8.logq = plain8.logq;
	cipher8.n = plain8.n;
	ZZ* bxP8 = new ZZ[N];
	ring.mult(bxP8, EncKey8.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP8, QQ);
	Key* key8 = new Key();
	ring.CRT(key8->rax, axP, nprimes);
	ring.CRT(key8->rbx, bxP8, nprimes);


	//Party9
	cipher9.logp = plain9.logp;
	cipher9.logq = plain9.logq;
	cipher9.n = plain9.n;
	ZZ* bxP9 = new ZZ[N];
	ring.mult(bxP9, EncKey9.sx, axP, npP, QQ);
	ring.subFromGaussAndEqual(bxP9, QQ);
	Key* key9 = new Key();
	ring.CRT(key9->rax, axP, nprimes);
	ring.CRT(key9->rbx, bxP9, nprimes);

	//Sum of public joint keys
	//Construct Public Key

	timeutils.start("joint_pk_generation");

	ZZ* bxSum = new ZZ[N];
	ring.addAndEqual(bxSum, bxP, QQ);
	ring.addAndEqual(bxSum, bxP1, QQ);
	ring.addAndEqual(bxSum, bxP2, QQ);
	ring.addAndEqual(bxSum, bxP3, QQ);
	ring.addAndEqual(bxSum, bxP4, QQ);
	ring.addAndEqual(bxSum, bxP5, QQ);
	ring.addAndEqual(bxSum, bxP6, QQ);
	ring.addAndEqual(bxSum, bxP7, QQ);
	ring.addAndEqual(bxSum, bxP8, QQ);
	ring.addAndEqual(bxSum, bxP9, QQ);
	
	Key* keySum = new Key();
	ring.CRT(keySum->rax, axP, nprimes);
	ring.CRT(keySum->rbx, bxSum, nprimes);
	timeutils.stop("joint_pk_generation");
	delete[] axP; delete[] bxP;


	//Encrypt Party0
	//timeutils.start("encryption_one");
	ring.multNTT(cipher.ax, vx, keySum->rax, npP, qQ);
	ring.addGaussAndEqual(cipher.ax, qQ);
	ring.multNTT(cipher.bx, vx, keySum->rbx, npP, qQ);
	ring.addGaussAndEqual(cipher.bx, qQ);
	ring.addAndEqual(cipher.bx, plain.mx, qQ);
	ring.rightShiftAndEqual(cipher.ax, logQ);
	ring.rightShiftAndEqual(cipher.bx, logQ);
	//timeutils.stop("encryption_one");

	//Encrypt Party1 -- to Partyn
	//...
	
	delete[] vx;
}

void TestScheme::encryptMsg_MKCKKS(Ciphertext& cipher, Plaintext& plain,SecretKey& secretK,SecretKey& pKey) {
	Ring ring;
	cipher.logp = plain.logp;
	cipher.logq = plain.logq;
	cipher.n = plain.n;
	ZZ qQ = ring.qpows[plain.logq + logQ];

	ZZ* vx = new ZZ[N];
	ring.sampleZO(vx);

	Key* key = Convert_to_key_structure(secretK);
	Key* publicKey = Convert_to_key_structure(pKey);

	long np = ceil((1 + logQQ + logN + 2)/(double)pbnd);
	ring.multNTT(cipher.ax, vx, key->rax, np, qQ);
	ring.addGaussAndEqual(cipher.ax, qQ);

	ring.multNTT(cipher.bx, vx, publicKey->rbx, np, qQ);
	ring.addGaussAndEqual(cipher.bx, qQ);
	delete[] vx;

	ring.addAndEqual(cipher.bx, plain.mx, qQ);

	ring.rightShiftAndEqual(cipher.ax, logQ);
	ring.rightShiftAndEqual(cipher.bx, logQ);
}


SecretKey TestScheme::Generate_public_key(SecretKey& secretKey) {
	Ring ring;	
	ZZ* ax = new ZZ[N];
	ZZ* bx = new ZZ[N];
	
	ZZ* ax_tmp = new ZZ[N];
	ax_tmp=ax;

	ZZ q = ring.qpows[logQ];
	ring.subAndEqual(ax,ax_tmp,q);
	ring.subAndEqual(ax,ax_tmp,q);

	long npB = ceil((1 + logQQ + logN + 2)/(double)pbnd);
	ring.sampleUniform2(ax, logQQ);
	ring.mult(bx, secretKey.sx, ax, npB, QQ);
	ring.subFromGaussAndEqual(bx, QQ);
	SecretKey publictKey(ring);
	publictKey.sx=bx;
	return publictKey;
}

Key* TestScheme::Convert_to_key_structure(SecretKey& secretKey) {
	Ring ring;
	
	ZZ* ax = new ZZ[N];
	ZZ* bx = new ZZ[N];

	long np = ceil((1 + logQQ + logN + 2)/(double)pbnd);
	ring.sampleUniform2(ax, logQQ);
	ring.mult(bx, secretKey.sx, ax, np, QQ);
	ring.subFromGaussAndEqual(bx, QQ);

	Key* key = new Key();
	ring.CRT(key->rax, ax, nprimes);
	ring.CRT(key->rbx, bx, nprimes);
	delete[] ax; delete[] bx;	
	return key;
}

//Ecnryption and Decryption via joint public key
void TestScheme::testEncrypt(long logq, long logp, long logn,string round,string trial) {
	TimeUtils timeutils;	
	int sum = 0;
	double x;
	ifstream inFile;
	long n= (1 << logn);
	ostringstream temp;
	temp << round;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	
	//Data import Party 0
	inFile.open("path_to_data_file/doc_T("+trial+")_run_"+round+".txt");
	long i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec[i] = tmp;
	i++;
	//cout << "Value = " << x << endl; 
	}
	inFile.close();
	srand(time(NULL));
	SetNumThreads(8);
	





	
	//Data import Party 1
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run2_"+round+".txt");
	i=0;
	if (!inFile) {
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec1[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();

	//Data import Party 2
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run3_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec2[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();

	//Data import Party 3
	complex<double>* mvec3 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run4_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec3[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 4
	complex<double>* mvec4 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run5_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec4[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 5
	complex<double>* mvec5 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run6_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec5[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 6
	complex<double>* mvec6 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run7_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec6[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 7
	complex<double>* mvec7 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run8_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec7[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 8
	complex<double>* mvec8 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run9_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec8[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	//Data import Party 9
	complex<double>* mvec9 = EvaluatorUtils::randomComplexArray(n);
	inFile.open("path_to_data_file/doc_T("+trial+")_run10_"+round+".txt");
	i=0;
	if (!inFile) {
	//cout << "Unable to open file";
	exit(1); // terminate with error
	}
	while (inFile >> x) {
	complex<double> tmp;
	tmp.real((double) x);
	tmp.imag((double) x);
	mvec9[i] = tmp;
	i++;

	//cout << "Value = " << x << endl; 
	}

	inFile.close();


	

	//Encoding
	//Part0 Preparation
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	cout << secretKey.sx;
	Plaintext plain;
	scheme.encode(plain, mvec, n, logp, logq);
	Ciphertext cipher;
	//Part1 Preparation
	Ring ring1;
	SecretKey secretKey1(ring1);
	Scheme scheme1(secretKey1, ring);
	Ciphertext cipher1;
	Plaintext plain1;
	scheme1.encode(plain1, mvec1, n, logp, logq);

	
	//Part2 Preparation
	Ring ring2;
	SecretKey secretKey2(ring2);
	Scheme scheme2(secretKey2, ring);
	Ciphertext cipher2;
	Plaintext plain2;
	scheme2.encode(plain2, mvec2, n, logp, logq);
	
	//Part3 Preparation
	Ring ring3;
	SecretKey secretKey3(ring3);
	Scheme scheme3(secretKey3, ring);
	Ciphertext cipher3;
	Plaintext plain3;
	scheme3.encode(plain3, mvec3, n, logp, logq);

	//Part4 Preparation
	Ring ring4;
	SecretKey secretKey4(ring4);
	Scheme scheme4(secretKey4, ring);
	Ciphertext cipher4;
	Plaintext plain4;
	scheme4.encode(plain4, mvec4, n, logp, logq);


	//Part5 Preparation
	Ring ring5;
	SecretKey secretKey5(ring5);
	Scheme scheme5(secretKey5, ring);
	Ciphertext cipher5;
	Plaintext plain5;
	scheme5.encode(plain5, mvec5, n, logp, logq);


	//Part6 Preparation
	Ring ring6;
	SecretKey secretKey6(ring6);
	Scheme scheme6(secretKey6, ring);
	Ciphertext cipher6;
	Plaintext plain6;
	scheme6.encode(plain6, mvec6, n, logp, logq);


	//Part7 Preparation
	Ring ring7;
	SecretKey secretKey7(ring7);
	Scheme scheme7(secretKey7, ring);
	Ciphertext cipher7;
	Plaintext plain7;
	scheme7.encode(plain7, mvec7, n, logp, logq);

	//Part8 Preparation
	Ring ring8;
	SecretKey secretKey8(ring8);
	Scheme scheme8(secretKey8, ring);
	Ciphertext cipher8;
	Plaintext plain8;
	scheme8.encode(plain8, mvec8, n, logp, logq);

	//Part9 Preparation
	Ring ring9;
	SecretKey secretKey9(ring9);
	Scheme scheme9(secretKey9, ring);
	Ciphertext cipher9;
	Plaintext plain9;
	scheme9.encode(plain9, mvec9, n, logp, logq);

	//Ecnryption
	SimpleEncryptMsg(cipher,plain,secretKey,cipher1,plain1,secretKey1,cipher2,plain2,secretKey2,cipher3,plain3,secretKey3,cipher4,plain4,secretKey4,cipher5,plain5,secretKey5,cipher6,plain6,secretKey6,cipher7,plain7,secretKey7,cipher8,plain8,secretKey8,cipher9,plain9,secretKey9);


	timeutils.start("ciphers_sum");
	//Ciphers sum
	Ring ring_1;
	Ciphertext cipherAdd;

	ZZ q1 = ring_1.qpows[cipher1.logq];
	ZZ q2 = ring_1.qpows[cipher2.logq];
	ZZ q3 = ring_1.qpows[cipher3.logq];
	ZZ q4 = ring_1.qpows[cipher4.logq];
	ZZ q5 = ring_1.qpows[cipher5.logq];
	ZZ q6 = ring_1.qpows[cipher6.logq];
	ZZ q7 = ring_1.qpows[cipher7.logq];
	ZZ q8 = ring_1.qpows[cipher8.logq];
	ZZ q9 = ring_1.qpows[cipher9.logq];

	cipherAdd.copyParams(cipher);
	
	ring.add(cipherAdd.ax, cipher.ax, cipher1.ax, q1);
	ring.add(cipherAdd.bx, cipher.bx, cipher1.bx, q1);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher2.ax, q2);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher2.bx, q2);
	
	ring.add(cipherAdd.ax, cipherAdd.ax, cipher3.ax, q3);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher3.bx, q3);
	
	ring.add(cipherAdd.ax, cipherAdd.ax, cipher4.ax, q4);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher4.bx, q4);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher5.ax, q5);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher5.bx, q5);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher6.ax, q6);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher6.bx, q6);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher7.ax, q7);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher7.bx, q7);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher8.ax, q8);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher8.bx, q8);

	ring.add(cipherAdd.ax, cipherAdd.ax, cipher9.ax, q9);
	ring.add(cipherAdd.bx, cipherAdd.bx, cipher9.bx, q9);
	timeutils.stop("ciphers_sum");



	ZZ* sx = new ZZ[N];
	ZZ* sx1 = new ZZ[N];
	ZZ* sx3 = new ZZ[N];
	ZZ* sx4 = new ZZ[N];
	ZZ* sx5 = new ZZ[N];
	ZZ* sx6 = new ZZ[N];
	ZZ* sx7 = new ZZ[N];
	ZZ* sx8 = new ZZ[N];
	ZZ* sx9 = new ZZ[N];
	ZZ* sx10 = new ZZ[N];
	
	//New TEST
	Plaintext plain_t;
	Plaintext plain_t1;
	Plaintext plain_t2;
	Plaintext plain_t3;
	Plaintext plain_t4;
	Plaintext plain_t5;
	Plaintext plain_t6;
	Plaintext plain_t7;
	Plaintext plain_t8;
	Plaintext plain_t9;
	Plaintext plain_t10;

	ZZ q = ring.qpows[cipher.logq];
	plain_t.logp = cipher.logp;
	plain_t.logq = cipher.logq;
	plain_t.n = cipher.n;

	plain_t1.logp = cipher1.logp;
	plain_t1.logq = cipher1.logq;
	plain_t1.n = cipher1.n;


	plain_t2.logp = cipher2.logp;
	plain_t2.logq = cipher2.logq;
	plain_t2.n = cipher2.n;


	plain_t3.logp = cipher3.logp;
	plain_t3.logq = cipher3.logq;
	plain_t3.n = cipher3.n;

	plain_t4.logp = cipher4.logp;
	plain_t4.logq = cipher4.logq;
	plain_t4.n = cipher4.n;

	plain_t5.logp = cipher5.logp;
	plain_t5.logq = cipher5.logq;
	plain_t5.n = cipher5.n;

	plain_t6.logp = cipher6.logp;
	plain_t6.logq = cipher6.logq;
	plain_t6.n = cipher6.n;

	plain_t7.logp = cipher7.logp;
	plain_t7.logq = cipher7.logq;
	plain_t7.n = cipher7.n;

	plain_t8.logp = cipher8.logp;
	plain_t8.logq = cipher8.logq;
	plain_t8.n = cipher8.n;

	plain_t9.logp = cipher9.logp;
	plain_t9.logq = cipher9.logq;
	plain_t9.n = cipher9.n;




	//Decryption share p0
	//timeutils.start("dec_share");
	long np = ceil((1 + cipher1.logq + logN + 2)/(double)pbnd);
	ring.mult(plain_t.mx, cipherAdd.ax, secretKey.sx, np, q);
	ring.mult(plain_t1.mx, cipherAdd.ax, secretKey1.sx, np, q1);
	ring.mult(plain_t2.mx, cipherAdd.ax, secretKey2.sx, np, q2);
	ring.mult(plain_t3.mx, cipherAdd.ax, secretKey3.sx, np, q3);
	ring.mult(plain_t4.mx, cipherAdd.ax, secretKey4.sx, np, q4);
	ring.mult(plain_t5.mx, cipherAdd.ax, secretKey5.sx, np, q5);
	ring.mult(plain_t6.mx, cipherAdd.ax, secretKey6.sx, np, q6);
	ring.mult(plain_t7.mx, cipherAdd.ax, secretKey7.sx, np, q7);
	ring.mult(plain_t8.mx, cipherAdd.ax, secretKey8.sx, np, q8);
	ring.mult(plain_t9.mx, cipherAdd.ax, secretKey9.sx, np, q9);
	
	ZZ qQ = ring.qpows[plain_t.logq + logQ];
	ring.addGaussAndEqual(plain_t.mx, qQ);
	ring.addAndEqual(plain_t.mx, plain_t1.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t2.mx, q);	
	ring.addAndEqual(plain_t.mx, plain_t3.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t4.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t5.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t6.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t7.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t8.mx, q);
	ring.addAndEqual(plain_t.mx, plain_t9.mx, q);


	//Add C0 to Di sum
	timeutils.start("add_C0");
	ring.addAndEqual(plain_t.mx, cipherAdd.bx, q);
	timeutils.stop("add_C0");

	complex<double>* res=scheme.decode(plain_t);

	StringUtils::showVec(res,10);
	//end of decryption
	
	return ;
	

}	

void TestScheme::testEncryptBySk(long logq, long logp, long logn) {
	cout << "!!! STARTTTTTT TEST ENCRYPT by SK !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
        cout << "-------Size of SK----" << endl;
	cout << secretKey.sx << endl;
        cout << "-------Size of SK----" << endl;
	cout << "-------Public keyyy----" << endl;
	Key* key = new Key();
	cout << key->rax << endl;
	cout << key->rbx << endl;
	cout <<Nnprimes << endl;
	
	

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;
	Ciphertext cipherAdd;

	timeutils.start("Encrypt by sk");
	scheme.encryptBySk(cipher, secretKey, mvec, n, logp, logq);
	timeutils.stop("Encrypt by sk");

	timeutils.start("Decrypt");
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	timeutils.stop("Decrypt");

	//StringUtils::compare(mvec, dvec, n, "val");

	cout << "!!! END TEST ENCRYPT By SK !!!" << endl;
	cout << "!!! Now Values of Cipher !!!" << endl;
	SerializationUtils sr;
	sr.writeCiphertext(cipher,"saved_cipher");
	cout << sizeof(cipher)<< endl;
	FILE *foot=fopen("exportedBin","w");
	fwrite(&cipher,sizeof(cipher),1,foot);
	ZZ q1 = ring.qpows[cipher.logq];
	ring.add(cipherAdd.ax, cipher.ax, cipher.ax, q1);
	ring.add(cipherAdd.bx, cipher.ax, cipher.bx, q1);
	cout << sizeof(cipherAdd)<< endl;
}

void TestScheme::testDecryptForShare(long logq, long logp, long logn, long logErrorBound) {
	cout << "!!! START TEST Decrypt for Share !!!" << endl;
	
	double sigma1 = 3.2 * sqrt(2);
	
	cout << "Note : encryption std is changed to sigma1 = " << sigma1 << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;

	timeutils.start("Encrypt by sk");
	scheme.encryptBySk(cipher, secretKey, mvec, n, logp, logq, sigma1);
	timeutils.stop("Encrypt by sk");

	timeutils.start("Decrypt by share");
	complex<double>* dvecShare = scheme.decryptForShare(secretKey, cipher, logErrorBound);
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	timeutils.stop("Decrypt by share");

	for (long i = 0; i < n; ++i) {
		cout << "---------------------" << endl;
		cout << "plain : " << i << " :" << mvec[i] << endl;
		cout << "decrypt : " << i << " :" << dvec[i] << endl;
		cout << "decryptForShare : " << i << " :" << dvecShare[i] << endl;
		cout << "dec error : " << i << " :" << (mvec[i]-dvec[i]) << endl;
		cout << "dec and decForShare error : " << i << " :" << (dvec[i]-dvecShare[i]) << endl;
		cout << "---------------------" << endl;
	}

	cout << "!!! END TEST Decrypt for Share !!!" << endl;
}

void TestScheme::testEncryptSingle(long logq, long logp) {
	cout << "!!! START TEST ENCRYPT SINGLE !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	complex<double> mval = EvaluatorUtils::randomComplex();
	Ciphertext cipher;

	timeutils.start("Encrypt Single");
	scheme.encryptSingle(cipher, mval, logp, logq);
	timeutils.stop("Encrypt Single");
	
	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval, "val");

	cout << "!!! END TEST ENCRYPT SINGLE !!!" << endl;

	//cout << cipher.ax;
	//cout << "-----------" << endl;
	//cout << cipher.bx;
	//cout << "-----------" << endl;
	//cout << "-----------" << endl;

	//cout << cipher.ax[0];
	//cout << "-----------" << endl;
	//cout << cipher.bx[0];
	cout << sizeof(cipher)<< endl;
	cout << sizeof(cipher.ax)<< endl;
	cout << sizeof(cipher.bx)<< endl;
	SerializationUtils sr;
	sr.writeCiphertext(cipher,"saved_cipher");
	

}

void TestScheme::testAdd(long logq, long logp, long logn) {
	cout << "!!! START TEST ADD !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* madd = new complex<double>[n];

	for(long i = 0; i < n; i++) {
		madd[i] = mvec1[i] + mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Addition");
	scheme.addAndEqual(cipher1, cipher2);
	timeutils.stop("Addition");

	complex<double>* dadd = scheme.decrypt(secretKey, cipher1);

	StringUtils::compare(madd, dadd, n, "add");

	cout << "!!! END TEST ADD !!!" << endl;
}

void TestScheme::testMult(long logq, long logp, long logn) {
	cout << "!!! START TEST MULT !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mmult = new complex<double>[n];
	for(long i = 0; i < n; i++) {
		mmult[i] = mvec1[i] * mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Multiplication");
	scheme.multAndEqual(cipher1, cipher2);
	timeutils.stop("Multiplication");
	timeutils.start("Decryption");
	complex<double>* dmult = scheme.decrypt(secretKey, cipher1);
	timeutils.stop("Decryption");
	StringUtils::compare(mmult, dmult, n, "mult");

	cout << "!!! END TEST MULT !!!" << endl;
}

void TestScheme::testiMult(long logq, long logp, long logn) {
	cout << "!!! START TEST i MULTIPLICATION !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* imvec = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		imvec[i].real(-mvec[i].imag());
		imvec[i].imag(mvec[i].real());
	}

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Multiplication by i");
	scheme.imultAndEqual(cipher);
	timeutils.stop("Multiplication by i");

	complex<double>* idvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(imvec, idvec, n, "imult");

	cout << "!!! END TEST i MULTIPLICATION !!!" << endl;
}


//----------------------------------------------------------------------------------
//   ROTATE & CONJUGATE
//----------------------------------------------------------------------------------


void TestScheme::testRotateFast(long logq, long logp, long logn, long logr) {
	cout << "!!! START TEST ROTATE FAST !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	long r = (1 << logr);
	scheme.addLeftRotKey(secretKey, r);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Left Rotate Fast");
	scheme.leftRotateFastAndEqual(cipher, r);
	timeutils.stop("Left Rotate Fast");

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	EvaluatorUtils::leftRotateAndEqual(mvec, n, r);
	StringUtils::compare(mvec, dvec, n, "rot");

	cout << "!!! END TEST ROTATE BY POWER OF 2 BATCH !!!" << endl;
}

void TestScheme::testConjugate(long logq, long logp, long logn) {
	cout << "!!! START TEST CONJUGATE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	scheme.addConjKey(secretKey);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvecconj = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvecconj[i] = conj(mvec[i]);
	}

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Conjugate");
	scheme.conjugateAndEqual(cipher);
	timeutils.stop("Conjugate");

	complex<double>* dvecconj = scheme.decrypt(secretKey, cipher);
	StringUtils::compare(mvecconj, dvecconj, n, "conj");

	cout << "!!! END TEST CONJUGATE !!!" << endl;
}


//----------------------------------------------------------------------------------
//   POWER & PRODUCT TESTS
//----------------------------------------------------------------------------------


void TestScheme::testPowerOf2(long logq, long logp, long logn, long logdeg) {
	cout << "!!! START TEST POWER OF 2 !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	long degree = 1 << logdeg;
	complex<double>* mvec = new complex<double>[n];
	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i] = EvaluatorUtils::randomCircle();
		mpow[i] = pow(mvec[i], degree);
	}

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power of 2");
	algo.powerOf2(cpow, cipher, logp, logdeg);
	timeutils.stop("Power of 2");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow2");

	cout << "!!! END TEST POWER OF 2 !!!" << endl;
}

//-----------------------------------------

void TestScheme::testPower(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST POWER !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n);
	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mpow[i] = pow(mvec[i], degree);
	}

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power");
	algo.power(cpow, cipher, logp, degree);
	timeutils.stop("Power");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow");

	cout << "!!! END TEST POWER !!!" << endl;
}


//----------------------------------------------------------------------------------
//   FUNCTION TESTS
//----------------------------------------------------------------------------------


void TestScheme::testInverse(long logq, long logp, long logn, long steps) {
	cout << "!!! START TEST INVERSE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n, 0.1);
	complex<double>* minv = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		minv[i] = 1. / mvec[i];
	}

	Ciphertext cipher, cinv;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Inverse");
	algo.inverse(cinv, cipher, logp, steps);
	timeutils.stop("Inverse");

	complex<double>* dinv = scheme.decrypt(secretKey, cinv);
	StringUtils::compare(minv, dinv, n, "inv");

	cout << "!!! END TEST INVERSE !!!" << endl;
}

void TestScheme::testLogarithm(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST LOGARITHM !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 0.1);
	complex<double>* mlog = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mlog[i] = log(mvec[i] + 1.);
	}

	Ciphertext cipher, clog;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(LOGARITHM);
	algo.function(clog, cipher, LOGARITHM, logp, degree);
	timeutils.stop(LOGARITHM);

	complex<double>* dlog = scheme.decrypt(secretKey, clog);
	StringUtils::compare(mlog, dlog, n, LOGARITHM);

	cout << "!!! END TEST LOGARITHM !!!" << endl;
}

void TestScheme::testExponent(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}

	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(EXPONENT);
	algo.function(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT);

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT !!!" << endl;
}

void TestScheme::testExponentLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT LAZY !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}
	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logQ);

	timeutils.start(EXPONENT + " lazy");
	algo.functionLazy(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT + " lazy");

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT LAZY !!!" << endl;
}

//-----------------------------------------

void TestScheme::testSigmoid(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID);
	algo.function(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID);

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID !!!" << endl;
}

void TestScheme::testSigmoidLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID LAZY !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID + " lazy");
	algo.functionLazy(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID + " lazy");

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID LAZY !!!" << endl;
}


void TestScheme::testWriteAndRead(long logq, long logp, long logSlots) {
	cout << "!!! START TEST WRITE AND READ !!!" << endl;

	cout << "!!! END TEST WRITE AND READ !!!" << endl;
}


void TestScheme::testBootstrap(long logq, long logp, long logSlots, long logT) {
	cout << "!!! START TEST BOOTSTRAP !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, logSlots, logq + 4);
	timeutils.stop("Key generated");

	long slots = (1 << logSlots);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(slots);

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, slots, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;

	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;
	cipher.logp = logq + 4;

	Ciphertext rot;
	timeutils.start("SubSum");
	for (long i = logSlots; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, (1 << i));
		scheme.addAndEqual(cipher, rot);
	}
	scheme.divByPo2AndEqual(cipher, logNh);
	timeutils.stop("SubSum");

	timeutils.start("CoeffToSlot");
	scheme.coeffToSlotAndEqual(cipher);
	timeutils.stop("CoeffToSlot");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	timeutils.start("SlotToCoeff");
	scheme.slotToCoeffAndEqual(cipher);
	timeutils.stop("SlotToCoeff");

	cipher.logp = logp;
	cout << "cipher logq after: " << cipher.logq << endl;

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(mvec, dvec, slots, "boot");

	cout << "!!! END TEST BOOTSRTAP !!!" << endl;
}

void TestScheme::testBootstrapSingleReal(long logq, long logp, long logT) {
	cout << "!!! START TEST BOOTSTRAP SINGLE REAL !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, 0, logq + 4);
	timeutils.stop("Key generated");

	double mval = EvaluatorUtils::randomReal();

	Ciphertext cipher;
	scheme.encryptSingle(cipher, mval, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;
	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;

	Ciphertext rot, cconj;
	timeutils.start("SubSum");
	for (long i = 0; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, 1 << i);
		scheme.addAndEqual(cipher, rot);
	}
	scheme.conjugate(cconj, cipher);
	scheme.addAndEqual(cipher, cconj);
	scheme.divByPo2AndEqual(cipher, logN);
	timeutils.stop("SubSum");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	cout << "cipher logq after: " << cipher.logq << endl;

	cipher.logp = logp;
	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval.real(), "boot");

	cout << "!!! END TEST BOOTSRTAP SINGLE REAL !!!" << endl;
}
