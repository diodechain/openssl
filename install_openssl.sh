# /bin/bash
echo "Prepare for building openssl......"
apt-get update -y && \
    apt-get install -y git build-essential pkg-config zip wget

# install openssl
echo "Build and install openssl......"
mkdir /usr/local/openssl
wget -O openssl.tar.gz https://github.com/openssl/openssl/archive/OpenSSL_1_0_2u.tar.gz && \
    [ "82fa58e3f273c53128c6fe7e3635ec8cda1319a10ce1ad50a987c3df0deeef05" = "$(sha256sum openssl.tar.gz | cut -d ' ' -f1)" ] && \
    tar -xzf openssl.tar.gz
cd ./openssl-OpenSSL_1_0_2u
./Configure no-ssl2 no-ssl3 no-dtls no-dtls1 no-idea no-mdc2 no-rc5 no-zlib --prefix=/usr/local/openssl
make depend && make && make install
export PKG_CONFIG_PATH=/usr/local/openssl/lib/pkgconfig

echo "Cleanup"
cd ..
rm -rf openssl.tar.gz
rm -rf openssl-OpenSSL_1_0_2u