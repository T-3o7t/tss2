tpm2 createprimary -C o -c primary.ctx -G rsa2048 -g sha256;
tpm2 create -C primary.ctx -u child.pub -r child.priv -G rsa2048;
tpm2 load -C primary.ctx -u child.pub -r child.priv -c child.ctx;
tpm2_evictcontrol \
  -C o \
  -c child.ctx \
  0x81010001
tpm2_readpublic -c child.ctx -o pub.pem -f pem
