//============================================================================
// Name        : OPENSSL_TEST.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <openssl/evp.h>	// hash
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <iostream>
#include <random>

namespace
{
	constexpr uint32_t EC_SIZE_256 = 32;
	constexpr uint32_t EC_SIZE_512 = 64;
	constexpr uint8_t ZERO = 0;

	// Create a key pair.
	int createKeyPairSecp256r1(EC_GROUP &curve, uint8_t *PrKey, uint8_t *PubKey)
	{
		int rv = -1;
		BIGNUM *BN_PrKey = NULL;
		EC_POINT *BN_PubKey = NULL;

		// Verify curve it is a Secp256r1
		if (EC_GROUP_get_curve_name(&curve) == NID_X9_62_prime256v1)
		{
			// Generate random BN_PrKey.
			const BIGNUM *order = EC_GROUP_get0_order(&curve);
			BIGNUM *prime = NULL, *a = NULL, *b = NULL;
			BIGNUM *zero = BN_bin2bn(&ZERO, sizeof(ZERO), NULL);
			EC_GROUP_get_curve(&curve, prime, a, b, NULL);
			bool keepIter = true;
			do
			{
				// RNG for prK
				for (uint32_t idx = 0; idx < EC_SIZE_256; idx++) { PrKey[idx] = rand(); }

				// Verify prK <= (n-1)
				BN_PrKey = BN_bin2bn(PrKey, EC_SIZE_256, NULL);
				if (BN_PrKey && (BN_cmp(BN_PrKey, zero) > 0) && (BN_cmp(BN_PrKey, order) < 0))
				{
					// BN_PubKey = [PrivKey] * G
					if (EC_POINT_mul(&curve, BN_PubKey, BN_PrKey, NULL, NULL, NULL))
					{
						// 1. Verify that Q is not the infinite point.
						if (EC_POINT_is_at_infinity(&curve, BN_PubKey))
							continue;

						// 2. Verify that xQ and yQ are properly represented elements of Fp (e.g., integers in
						// the interval [0, p − 1] if Fp is a prime field.
						BIGNUM *x = NULL, *y = NULL;
						EC_POINT_get_affine_coordinates(&curve, BN_PubKey, x, y, NULL);
						if ((BN_cmp(zero, x) >= 0) && (BN_cmp(x, prime) < 0) &&
							(BN_cmp(zero, y) >= 0) && (BN_cmp(y, prime) < 0))
							continue;

						BN_bn2bin(x, PubKey);
						BN_bn2bin(y, &PubKey[EC_SIZE_256]);

						BN_free(x);
						BN_free(y);

						// 3. Verify that Q satisfies the elliptic curve equation defined by a and b.
						if (EC_POINT_is_on_curve(&curve, BN_PubKey, NULL))
							keepIter = false;
					}
				}
			}
			while (keepIter);

			BN_free(zero);
			BN_free(b);
			BN_free(a);
			BN_free(prime);
			BN_free((BIGNUM *)order);
			BN_free(BN_PrKey);
			EC_POINT_free(BN_PubKey);

			rv = 0;
		}

		return rv;
	}

	// Calculate Public Key
	int calcPubKeySecp256(EC_GROUP &curve, uint8_t *PrKey, uint8_t *PubKey)
	{
		int rv = -1;
		BIGNUM *BN_PrKey = NULL;
		EC_POINT *BN_PubKey = NULL;
		bool valid = true;

		// Verify curve it is a Secp256r1
		if (EC_GROUP_get_curve_name(&curve) == NID_X9_62_prime256v1)
		{
			// Generate random BN_PrKey.
			BIGNUM *prime = NULL, *a = NULL, *b = NULL;
			BIGNUM *zero = BN_bin2bn(&ZERO, sizeof(ZERO), NULL);
			EC_GROUP_get_curve(&curve, prime, a, b, NULL);

			BN_PrKey = BN_bin2bn(PrKey, EC_SIZE_256, NULL);
			if (BN_PrKey)
			{
				// BN_PubKey = [PrivKey] * G
				BN_PubKey = EC_POINT_new(&curve);
				if (EC_POINT_mul(&curve, BN_PubKey, BN_PrKey, NULL, NULL, NULL))
				{
					// 1. Verify that Q is not the infinite point.
					if (EC_POINT_is_at_infinity(&curve, BN_PubKey))
						valid = false;

					// 2. Verify that xQ and yQ are properly represented elements of Fp (e.g., integers in
					// the interval [0, p − 1] if Fp is a prime field.
					BIGNUM *x = BN_new();
					BIGNUM *y = BN_new();
					if (!EC_POINT_get_affine_coordinates(&curve, BN_PubKey, x, y, NULL) &&
						(BN_cmp(zero, x) >= 0) && (BN_cmp(x, prime) < 0) &&
						(BN_cmp(zero, y) >= 0) && (BN_cmp(y, prime) < 0))
						valid = false;

					BN_bn2bin(x, PubKey);
					BN_bn2bin(y, &PubKey[EC_SIZE_256]);

					BN_free(x);
					BN_free(y);

					// 3. Verify that Q satisfies the elliptic curve equation defined by a and b.
					if (valid && EC_POINT_is_on_curve(&curve, BN_PubKey, NULL))
						rv = 0;
				}
			}

			BN_free(zero);
			BN_free(prime);
			BN_free(BN_PrKey);
			EC_POINT_free(BN_PubKey);
		}

		return rv;
	}
}

int main ()
{

	// HASH - 256
	const EVP_MD * sha256 = EVP_sha256();		// Sha256 structure
	EVP_MD_CTX * ctxSha256 = EVP_MD_CTX_new();  // Create context

	// Digest data
	const uint8_t textplain[] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t textsha256[32];
	int rv;
	rv = EVP_DigestInit(ctxSha256, sha256);
	rv = EVP_DigestUpdate(ctxSha256, textplain, sizeof(textplain));
	rv = EVP_DigestFinal(ctxSha256, textsha256, NULL);

	EVP_MD_CTX_free(ctxSha256);		// Destroy context


	// AES-ECB
	const EVP_CIPHER * aes256_ecb = EVP_aes_256_ecb();		// AES 256 ECB structure
	EVP_CIPHER_CTX * ctxAes256Ecb = EVP_CIPHER_CTX_new();	// Context for AES 256 ECB

	uint8_t keyAes256Ecb[32] = {0x00};			// KEY AES 256 ECB
	keyAes256Ecb[0] = 0x80;
	uint8_t *ivAes256Ecb = NULL;	// NO IV for AES ECB
	uint8_t plaintextAes256Ecb[16] = {0x00};
	uint8_t ciphertextAes256Ecb[16];
	int outlEcb;
	rv = EVP_EncryptInit(ctxAes256Ecb, aes256_ecb, keyAes256Ecb, ivAes256Ecb);
	rv = EVP_EncryptUpdate(ctxAes256Ecb, ciphertextAes256Ecb, &outlEcb, plaintextAes256Ecb, 16);
//	rv = EVP_EncryptFinal(ctxAes256Ecb, ciphertextAes256Ecb, &outlEcb);

	EVP_CIPHER_CTX_free(ctxAes256Ecb);


	// AES-CBC
	const EVP_CIPHER * aes256_cbc = EVP_aes_256_cbc();		// AES 256 CBC structure
	EVP_CIPHER_CTX * ctxAes256Cbc = EVP_CIPHER_CTX_new();	// Context for AES 256 CBC

	uint8_t keyAes256Cbc[32] = {0x00};			// KEY AES 256 CBC
	uint8_t ivAes256Cbc[16] = {0x00};	// IV for AES CBC
	uint8_t plaintextAes256Cbc[16] = {0x00};
	plaintextAes256Cbc[0] = 0x80;
	uint8_t ciphertextAes256Cbc[16];
	int outlCbc;
	rv = EVP_EncryptInit(ctxAes256Cbc, aes256_cbc, keyAes256Cbc, ivAes256Cbc);
	rv = EVP_EncryptUpdate(ctxAes256Cbc, ciphertextAes256Cbc, &outlCbc, plaintextAes256Cbc, 16);
//	rv = EVP_EncryptFinal(ctxAes256Cbc, ciphertextAes256Cbc, &outlCbc);

	EVP_CIPHER_CTX_free(ctxAes256Cbc);


	// KEY PAIR GENERATION
	EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (curve != NULL)
	{
		uint8_t PrKey[EC_SIZE_256] = {0xc9, 0x80, 0x68, 0x98, 0xa0, 0x33, 0x49,
				0x16, 0xc8, 0x60, 0x74, 0x88, 0x80, 0xa5, 0x41, 0xf0, 0x93,
				0xb5, 0x79, 0xa9, 0xb1, 0xf3, 0x29, 0x34, 0xd8, 0x6c, 0x36,
				0x3c, 0x39, 0x80, 0x03, 0x57};
		uint8_t PubKey[2*EC_SIZE_256];
		calcPubKeySecp256(*curve, PrKey, PubKey);
	}

	// KEY SIGNATURE


	return 0;
}
