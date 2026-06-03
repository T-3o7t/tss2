#ifndef QUOTE
#define QUOTE

#include <string.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys);
static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys);
static void save_signature(TPMT_SIGNATURE *sig, const char *path);
static void save_quote(TPM2B_ATTEST *quote, const char *path);

#endif
