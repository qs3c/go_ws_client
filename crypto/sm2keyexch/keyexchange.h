#pragma once
#pragma warning(push)
#pragma warning(disable:4996)
#define OPENSSL_API_COMPAT 0x10100000L

#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <crypto/sm2.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
// 2: 引入 BN 库,CGO的编译器和MSVC的编译器不一样，需要显示include而不是包含在ec.h中
#include <openssl/bn.h>



#define SM2_DEFAULT_POINT_CONVERSION_FORM	 4


typedef void* (*KDF_FUNC)(const void* in, size_t inlen, void* out, size_t* outlen);

struct sm2_kap_ctx_st {

	const EVP_MD* id_dgst_md;
	const EVP_MD* kdf_md;
	const EVP_MD* checksum_md;
	point_conversion_form_t point_form;
	KDF_FUNC kdf;

	int is_initiator;
	int do_checksum;

	EC_KEY* ec_key;
	unsigned char id_dgst[EVP_MAX_MD_SIZE];
	unsigned int id_dgstlen;

	EC_KEY* remote_pubkey;
	unsigned char remote_id_dgst[EVP_MAX_MD_SIZE];
	unsigned int remote_id_dgstlen;

	const EC_GROUP* group;
	BN_CTX* bn_ctx;
	BIGNUM* order;
	BIGNUM* two_pow_w;

	BIGNUM* t;
	EC_POINT* point;
	unsigned char pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS + 7) / 4];
	unsigned char checksum[EVP_MAX_MD_SIZE];

};

typedef struct sm2_kap_ctx_st SM2_KAP_CTX;


int SM2_get_public_key_data(EC_KEY* ec_key, unsigned char* out, size_t* outlen);
int SM2_compute_id_digest(const EVP_MD* md, const char* id, size_t idlen, unsigned char* out, size_t* outlen, EC_KEY* ec_key);
void SM2_KAP_CTX_cleanup(SM2_KAP_CTX* ctx);
int SM2_KAP_CTX_init(SM2_KAP_CTX* ctx, EC_KEY* ec_key, const char* id, size_t idlen, EC_KEY* remote_pubkey, const char* rid, size_t ridlen, int is_initiator, int do_checksum);
int SM2_KAP_prepare(SM2_KAP_CTX* ctx, unsigned char* ephem_point, size_t* ephem_point_len);
int SM2_KAP_compute_key(SM2_KAP_CTX* ctx, const unsigned char* remote_point, size_t remote_point_len, unsigned char* key, size_t keylen, unsigned char* checksum, size_t* checksumlen);
int SM2_KAP_final_check(SM2_KAP_CTX* ctx, const unsigned char* checksum, size_t checksumlen);


 
