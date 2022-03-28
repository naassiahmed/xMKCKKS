/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef HEAAN_TESTSCHEME_H_
#define HEAAN_TESTSCHEME_H_
#include "Plaintext.h"
#include "Key.h"
#include "StringUtils.h"
#include "Ciphertext.h"
#include "Ring.h"
#include "SecretKey.h"
class TestScheme {
public:


	//----------------------------------------------------------------------------------
	//   STANDARD TESTS
	//----------------------------------------------------------------------------------
	
	
	static void Benchmark(long logq, long logp, long logn,int batch);
	static void testEncrypt(long logq, long logp, long logn,string round,string trial);
	
	static SecretKey Generate_public_key(SecretKey& secretKey);
	
	static void encryptMsg_MKCKKS(Ciphertext& cipher, Plaintext& plain,SecretKey& secretK,SecretKey& publicKey);
	
	static void SimpleEncryptMsg(Ciphertext& cipher, Plaintext& plain,SecretKey& EncKey,Ciphertext& cipher1, Plaintext& plain1,SecretKey& EncKey1,Ciphertext& cipher2, Plaintext& plain2,SecretKey& EncKey2,Ciphertext& cipher3, Plaintext& plain3,SecretKey& EncKey3,Ciphertext& cipher4, Plaintext& plain4,SecretKey& EncKey4,Ciphertext& cipher5, Plaintext& plain5,SecretKey& EncKey5,Ciphertext& cipher6, Plaintext& plain6,SecretKey& EncKey6,Ciphertext& cipher7, Plaintext& plain7,SecretKey& EncKey7,Ciphertext& cipher8, Plaintext& plain8,SecretKey& EncKey8,Ciphertext& cipher9, Plaintext& plain9,SecretKey& EncKey9);

	static Key* Convert_to_key_structure(SecretKey& secretKey);
	
	static void testEncryptBySk(long logq, long logp, long logn);
	
	static void testDecryptForShare(long logq, long logp, long logn, long logErrorBound);
	
	static void testEncryptSingle(long logq, long logp);
	
	static void testAdd(long logq, long logp, long logn);
	
	static void testMult(long logq, long logp, long logn);
	
	static void testiMult(long logq, long logp, long logn);


	//----------------------------------------------------------------------------------
	//   ROTATE & CONJUGATE TESTS
	//----------------------------------------------------------------------------------


	static void testRotateFast(long logq, long logp, long logn, long r);

	static void testConjugate(long logq, long logp, long logn);


	//----------------------------------------------------------------------------------
	//   POWER & PRODUCT TESTS
	//----------------------------------------------------------------------------------


	static void testPowerOf2(long logq, long logp, long logn, long logdeg);

	static void testPower(long logq, long logp, long logn, long degree);


	//----------------------------------------------------------------------------------
	//   FUNCTION TESTS
	//----------------------------------------------------------------------------------


	static void testInverse(long logq, long logp, long logn, long steps);

	static void testLogarithm(long logq, long logp, long logn, long degree);

	static void testExponent(long logq, long logp, long logn, long degree);

	static void testExponentLazy(long logq, long logp, long logn, long degree);

	static void testSigmoid(long logq, long logp, long logn, long degree);

	static void testSigmoidLazy(long logq, long logp, long logn, long degree);


	//----------------------------------------------------------------------------------
	//   BOOTSTRAPPING TESTS
	//----------------------------------------------------------------------------------
    

	static void testBootstrap(long logq, long logp, long logn, long logT);

	static void testBootstrapSingleReal(long logq, long logp, long logT);
    
    static void testWriteAndRead(long logq, long logp, long logn);

    
};

#endif
