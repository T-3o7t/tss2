# myTPM

- cc -o Signature Sig.c -ltss2-esys -ltss2-mu -ltss2-tctildr
- cc -o verify_tpm Verify_tpm.c -ltss2-esys -ltss2-tctildr -lssl -lcrypto
- cc -o verify_o verify_o.c -lssl -lcrypto

- ./Signature data.txt
- ./verify_tpm data.txt
- ./verify_o pub.pem data.txt sig.bin

