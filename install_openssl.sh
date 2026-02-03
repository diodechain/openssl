# /bin/bash
export VSN=1.1.1w
export PREFIX=/usr/local/openssl

if [ "$OS" == "Windows_NT" ]; then
    export PREFIX=C:/msys64/$PREFIX
fi

# install openssl
echo "Build and install openssl......"
$SUDO mkdir -p $PREFIX/ssl && \
    wget https://www.openssl.org/source/openssl-$VSN.tar.gz && \
    [ "cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8" = "$(sha256sum openssl-$VSN.tar.gz | cut -d ' ' -f1)" ] && \
    tar xzf openssl-$VSN.tar.gz && \
    cd openssl-$VSN && \
    ./config no-ssl2 no-ssl3 no-dtls no-dtls1 no-idea no-mdc2 no-rc5 no-zlib --prefix=$PREFIX "$@" && \
    make depend && make && $SUDO make install_sw install_ssldirs && \
    $SUDO cp -R include/internal $PREFIX/include && \
    $SUDO cp *.h $PREFIX/ && \
    $SUDO cp ssl/*.h $PREFIX/ssl/ && \
    $SUDO cp -R ssl/record ssl/statem $PREFIX/ssl/ && \
    ls -lha $PREFIX/ssl
