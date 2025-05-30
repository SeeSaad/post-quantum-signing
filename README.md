Steps for building the code:

1 - Build liboqs according to the official tutorial:
https://github.com/open-quantum-safe/liboqs.git

Instead of building the whole library, we can build exactly the parts we are interested in:

1 - Install all the dependencies for liboqs.

2 - build liboqs.

After building, the environment is ready to compile the code:

Example:
```
gcc -Ibuild/include -Lbuild/lib code_using_liboqs.c -o code -loqs -lcrypto 
```



===========================================

Steps executed on a Ubuntu instance in AWS:

===========================================

Update and install dependencies:
```
sudo apt update && sudo apt upgrade -y
sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
sync
sudo reboot
```

Build liboqs:
```
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja .. -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65"
ninja
```

Setup environment for testing:
```
mkdir ~/ML-DSA
cd ~/ML-DSA/
git clone https://github.com/SeeSaad/post-quantum-signing.git
cp post-quantum-signing/ML_DSA* ~/liboqs/
cd ~/liboqs/
gcc -Ibuild/include -Lbuild/lib ML-DSA-65_gen_keys.c -o keygen -loqs -lcrypto          
gcc -Ibuild/include -Lbuild/lib ML-DSA_sign_file.c -o sign -loqs -lcrypto    
gcc -Ibuild/include -Lbuild/lib ML-DSA_verify.c -o verify -loqs -lcrypto 
mv keygen sign verify ~/ML-DSA/
```

Usage:
`./keygen` -> Generate public and private signature
`./sign  <secret_key_file> <file_to_sign>` -> Sign file (stores signature in file.sig)
`./verify <public_key_file> <signed_file> <signature_file>` -> Verify signature, prints out confirmation message

Time benchmarking:
```
cd ~/ML-DSA/
cp post-quantum-signing/time_keygen.sh ./
chmod +x time_keygen.sh
sudo apt install hyperfine

./time_keygen.sh
hyperfine --runs 30 "./sign secret_key.bin test.txt"
hyperfine --runs 30 "./verify public_key.bin test.txt test.txt.sig"
```

Benchmarking other signature algorithms:
RSA (2048b):
```
hyperfine --runs 30 "openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048"
hyperfine --runs 30 "openssl rsa -pubout -in private.pem -out public.pem"
hyperfine --runs 30 "openssl dgst -sha256 -sign private.pem -out test.txt.sig test.txt"
hyperfine --runs 30 "openssl dgst -sha256 -verify public.pem -signature test.txt.sig test.txt"
```

RSA (3072b):
```
hyperfine --runs 30 "openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:3072"
hyperfine --runs 30 "openssl rsa -pubout -in private.pem -out public.pem"
hyperfine --runs 30 "openssl dgst -sha256 -sign private.pem -out test.txt.sig test.txt"
hyperfine --runs 30 "openssl dgst -sha256 -verify public.pem -signature test.txt.sig test.txt"
```

ECDSA (ECC P-256):
```
hyperfine --runs 30 "openssl ecparam -name prime256v1 -genkey -noout -out private.pem"
hyperfine --runs 30 "openssl ec -in private.pem -pubout -out public.pem"
hyperfine --runs 30 "openssl dgst -sha256 -sign private.pem -out test.txt.sig test.txt"
hyperfine --runs 30 "openssl dgst -sha256 -verify public.pem -signature test.txt.sig test.txt"
```

EdDSA (Ed25519):
EdDSA did not work with the current version of openssl in Ubuntu(3.0.x), In order to run the following commands, installing the newest (current) version of openssl is necessary.

```
wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
tar -xf openssl-3.5.0.tar.gz
cd openssl-3.5.0

./Configure --prefix=/home/ubuntu/ssl --openssldir=/home/ubuntu/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'
make -j$(nproc)
make install
```

To use the newest version:
```
export PATH="$HOME/ssl/bin:$PATH"
```

EdDSA (Ed25519):
```
hyperfine --runs 30 "openssl genpkey -algorithm ED25519 -out private.pem"
```

ML-DSA (openssl 3.5.0):
```
hyperfine --runs 30 "openssl genpkey -algorithm ML-DSA-44 -out private.pem"
hyperfine --runs 30 "openssl genpkey -algorithm ML-DSA-65 -out private.pem"
hyperfine --runs 30 "openssl genpkey -algorithm ML-DSA-87 -out private.pem"
```
```
hyperfine --runs 30 "openssl genpkey -algorithm ML-DSA-XX -out private.pem"
hyperfine --runs 30 "openssl pkey -in private.pem -pubout -out public.pem"
hyperfine --runs 30 "openssl pkeyutl -sign -inkey private.pem -in test.txt -out test.txt.sig"
hyperfine --runs 30 "openssl pkeyutl -verify -pubin -inkey public.pem -sigfile test.txt.sig -in test.txt"
```
