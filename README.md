# myTPM

cc -o Signature Sig.c -ltss2-esys -ltss2-mu -ltss2-tctildr
cc -o tpm_verify Verify.c -ltss2-esys -ltss2-tctildr -lssl -lcrypto

./Signature data.txt
./tpm_verify
