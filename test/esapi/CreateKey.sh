mkdir -p ~/github/myTPM/keys;
cd ~/github/myTPM/keys;

tpm2 createprimary -C o -c primary.ctx -G rsa2048 -g sha256;
tpm2 create -C primary.ctx -u ak.pub -r ak.priv -G rsa2048;
tpm2 load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx;
tpm2 evictcontrol -C o -c ak.ctx 0x81010100;
tpm2 getcap handles-persistent;

