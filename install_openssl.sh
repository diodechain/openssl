# /bin/bash
export VSN=1.1.1k
export PREFIX=/usr/local/openssl

# install openssl
echo "Build and install openssl......"
$SUDO mkdir -p $PREFIX && \
    wget https://www.openssl.org/source/openssl-$VSN.tar.gz && \
    [ "892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5" = "$(sha256sum openssl-$VSN.tar.gz | cut -d ' ' -f1)" ] && \
    tar xzf openssl-$VSN.tar.gz && \
    cd openssl-$VSN && \
    ./config no-ssl2 no-ssl3 no-dtls no-dtls1 no-idea no-mdc2 no-rc5 no-zlib --prefix=$PREFIX && \
    make depend && make && $SUDO make install_sw install_ssldirs && \
    $SUDO cp -R include/internal $PREFIX/include && \
    $SUDO cp *.h $PREFIX/ && \
    $SUDO cp ssl/*.h $PREFIX/ssl/ && \
    $SUDO cp -R ssl/record ssl/statem $PREFIX/ssl/
