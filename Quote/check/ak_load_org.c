#include "quote_check.h"

bool ak_load(TPM2B_PUBLIC *ak_pub, EVP_PKEY **pkey){

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (EVP_PKEY_fromdata_init(ctx) <= 0)
    	return false;
	
	const BYTE *modulus = ak_pub->publicArea.unique.rsa.buffer;
	UINT16 modulus_size = ak_pub->publicArea.unique.rsa.size;
	UINT32 exponent = ak_pub->publicArea.parameters.rsaDetail.exponent;

	BIGNUM *n = BN_bin2bn(modulus, modulus_size, NULL);
	BIGNUM *e = BN_new();
	BN_set_word(e, exponent == 0 ? 65537 : exponent);

	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	if (EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
		return false;

	BN_free(n);
	BN_free(e);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);

	return (*pkey != NULL);
}
