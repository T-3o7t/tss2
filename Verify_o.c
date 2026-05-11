#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int verify_signature(const char *pubkey_file, const char *data_file, const char *sig_file){
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    FILE *fp = NULL;
    unsigned char *sig = NULL;
    unsigned char m[EVP_MAX_MD_SIZE];
    size_t sig_len, m_len;
    int ret = 1;

    fp = fopen(pubkey_file, "r");
    if (!fp) {
        perror("fopen pubkey");
        goto cleanup;
    }
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "PEM_read_PUBKEY failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx || !EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto cleanup;
    }

    fp = fopen(data_file, "rb");
    if (!fp) {
        perror("fopen data");
        goto cleanup;
    }
    
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (!EVP_DigestVerifyUpdate(mdctx, buf, n)) {
            fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
            fclose(fp);
            goto cleanup;
        }
    }
    fclose(fp);

    fp = fopen(sig_file, "rb");
    if (!fp) {
        perror("fopen sig");
        goto cleanup;
    }
    fseek(fp, 0, SEEK_END);
    sig_len = ftell(fp);
    rewind(fp);
    sig = malloc(sig_len);
    if (fread(sig, 1, sig_len, fp) != sig_len) {
        perror("fread sig");
        fclose(fp);
        free(sig);
        goto cleanup;
    }
    fclose(fp);

    if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) > 0) {
        printf("Verified OK\n");
        ret = 0;
    } else {
        printf("Verification Failure\n");
        ERR_print_errors_fp(stderr);
    }

    cleanup:
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        free(sig);
        return ret;
}

int main(int argc, char *argv[]){
    if (argc != 4) {
        fprintf(stderr, "Usage: %s pub.pem data.txt sig.bin\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    return verify_signature(argv[1], argv[2], argv[3]);
}
