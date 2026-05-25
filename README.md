# myTPM Usage
- Create "data.txt" and "data_mod.txt" and write messages in each file
```bash
git clone https://github.com/T-3o7t/myTPM.git

./CreateKey.sh

echo message > data.txt

cc -o Signature Signature_esys.c -ltss2-esys -ltss2-mu -ltss2-tctildr
cc -o verify_tpm Verify_tpm_esys.c -ltss2-esys -ltss2-tctildr -lssl -lcrypto
cc -o verify_o Verify_pensslo.c -lssl -lcrypto
cc -o test_sys Test_sys.c -ltss2-tctildr -ltss2-sys -ltss2-rc

./Signature data.txt
./verify_tpm data.txt
./verify_o pub.pem data.txt sig.bin
./test_sys data.txt data_mod.txt
```
