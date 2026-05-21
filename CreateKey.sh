tpm2 createprimary -C o -c primary.ctx -G rsa2048 -g sha256;
tpm2 create -C primary.ctx -u hmac.pub -r hmac.priv -G keyedhash ;
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx;
tpm2 evictcontrol -C o -c hmac.ctx 0x81010001;

tpm2 create -C primary.ctx -u sign.pub -r sign.priv -G rsa2048;
tpm2 load -C primary.ctx -u sign.pub -r sign.priv -c sign.ctx;
tpm2 evictcontrol -C o -c sign.ctx 0x81010010;
tpm2 getcap handles-persistent;

tpm2_readpublic -c 0x81010001;
tpm2_readpublic -c 0x81010010;

