#include "quote_check.h"

bool ak_load(TPM2B_PUBLIC *ak_pub, EVP_PKEY **pkey){
	bool ret = false;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;

    const BYTE *modulus;
    UINT16 modulus_size;
    UINT32 exponent;

    if (ak_pub->publicArea.type != TPM2_ALG_RSA)
        return false;

    modulus = ak_pub->publicArea.unique.rsa.buffer;
    modulus_size = ak_pub->publicArea.unique.rsa.size;
    exponent = ak_pub->publicArea.parameters.rsaDetail.exponent;

    if (exponent == 0)
        exponent = 65537;

    n = BN_bin2bn(modulus, modulus_size, NULL);
    e = BN_new();
    if (!n || !e)
        goto cleanup;

    if (!BN_set_word(e, exponent))
        goto cleanup;

    bld = OSSL_PARAM_BLD_new();
    if (!bld)
        goto cleanup;

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        goto cleanup;

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        goto cleanup;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params)
        goto cleanup;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_fromdata(ctx, pkey,
            EVP_PKEY_PUBLIC_KEY, params) <= 0)
        goto cleanup;

    ret = true;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);

    return ret;
}
