#ifndef QUOTE_CHECK 
#define QUOTE_CHECK

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_mu.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

bool ak_load(TPM2B_PUBLIC *ak_pub, EVP_PKEY **pkey);

#endif
