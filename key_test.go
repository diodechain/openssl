// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	pem_pkg "encoding/pem"
	"io/ioutil"
	"testing"
)

func TestMarshal(t *testing.T) {
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	privateBlock, _ := pem_pkg.Decode(keyBytes)
	key, err = LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, certBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", certBytes, 0644)
		t.Fatal("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, keyBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", keyBytes, 0644)
		t.Fatal("invalid private key pem bytes")
	}
	tls_cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_key, ok := tls_cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("FASDFASDF")
	}
	_ = tls_key

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der := x509.MarshalPKCS1PrivateKey(tls_key)
	if !bytes.Equal(der, tls_der) {
		t.Fatalf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tls_der))
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err = x509.MarshalPKIXPublicKey(&tls_key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	tls_pem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Bytes: tls_der})
	if !bytes.Equal(pem, tls_pem) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", tls_pem, 0644)
		t.Fatal("invalid public key pem bytes")
	}

	loaded_pubkey_from_pem, err := LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	loaded_pubkey_from_der, err := LoadPublicKeyFromDER(der)
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_pem, err := loaded_pubkey_from_pem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_der, err := loaded_pubkey_from_der.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(new_der_from_der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	if !bytes.Equal(new_der_from_pem, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_pem)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}
}

func TestGenerate(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateRSAKeyWithExponent(1024, 65537)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateEC(t *testing.T) {
	key, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalECPrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalECPublicKeyBytes(Prime256v1, KeyConversionCompressed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalECPublicKeyBytes(Prime256v1, KeyConversionUncompressed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalECPublicKeyBytes(Prime256v1, KeyConversionHybrid)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateSecp256k1(t *testing.T) {
	key, err := GenerateECKey(Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSign(t *testing.T) {
	key, _ := GenerateRSAKey(1024)
	data := []byte("the quick brown fox jumps over the lazy dog")
	_, err := key.SignPKCS1v15(SHA1_Method, data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.SignPKCS1v15(SHA256_Method, data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.SignPKCS1v15(SHA512_Method, data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignEC(t *testing.T) {
	t.Parallel()

	key, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sha1", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA1_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA1_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sha256", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA256_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA256_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sha512", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA512_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA512_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})
}

// ECPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ECPublicKey ec public key format
// see (maybe): https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
type ECPublicKey struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters []byte `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

func extractECPrivateKeyBytesFromDer(derD []byte) []byte {
	var privKey ECPrivateKey
	if _, err := asn1.Unmarshal(derD, &privKey); err != nil {
		return nil
	}
	return privKey.PrivateKey
}
func extractECPublicKeyBytesFromDer(derQ []byte) []byte {
	var pubKey ECPublicKey
	if _, err := asn1.Unmarshal(derQ, &pubKey); err != nil {
		return nil
	}
	return pubKey.PublicKey.Bytes
}

func TestMarshalEC(t *testing.T) {
	key, err := LoadPrivateKeyFromPEM(prime256v1KeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(prime256v1CertBytes)
	if err != nil {
		t.Fatal(err)
	}

	privateBlock, _ := pem_pkg.Decode(prime256v1KeyBytes)
	key, err = LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, prime256v1CertBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", prime256v1CertBytes, 0644)
		t.Fatal("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, prime256v1KeyBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", prime256v1KeyBytes, 0644)
		t.Fatal("invalid private key pem bytes")
	}
	tls_cert, err := tls.X509KeyPair(prime256v1CertBytes, prime256v1KeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_key, ok := tls_cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("FASDFASDF")
	}
	_ = tls_key

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err := x509.MarshalECPrivateKey(tls_key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		t.Fatalf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tls_der))
	}

	pbyte, err := key.MarshalECPrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	tls_pbyte := extractECPrivateKeyBytesFromDer(tls_der)
	if !bytes.Equal(pbyte, tls_pbyte) {
		ioutil.WriteFile("generated", []byte(hex.Dump(pbyte)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_pbyte)), 0644)
		t.Fatal("invalid private key bytes")
	}

	loaded_priv_from_bytes, err := LoadECPrivateKeyFromBytes(Prime256v1, pbyte)
	if err != nil {
		t.Fatal(err)
	}
	tls_pbyte, err = loaded_priv_from_bytes.MarshalECPrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pbyte, tls_pbyte) {
		ioutil.WriteFile("generated", []byte(hex.Dump(pbyte)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_pbyte)), 0644)
		t.Fatal("invalid private key bytes")
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err = x509.MarshalPKIXPublicKey(&tls_key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	pbyte, err = key.MarshalECPublicKeyBytes(Prime256v1, KeyConversionUncompressed)
	if err != nil {
		t.Fatal(err)
	}
	tls_pbyte = extractECPublicKeyBytesFromDer(tls_der)
	if !bytes.Equal(pbyte, tls_pbyte) {
		ioutil.WriteFile("generated", []byte(hex.Dump(pbyte)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_pbyte)), 0644)
		t.Fatal("invalid public key bytes")
	}

	loaded_pub_from_bytes, err := LoadECPublicKeyFromBytes(Prime256v1, pbyte)
	if err != nil {
		t.Fatal(err)
	}
	tls_pbyte, err = loaded_pub_from_bytes.MarshalECPublicKeyBytes(Prime256v1, KeyConversionUncompressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pbyte, tls_pbyte) {
		ioutil.WriteFile("generated", []byte(hex.Dump(pbyte)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_pbyte)), 0644)
		t.Fatal("invalid private key bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	tls_pem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Bytes: tls_der})
	if !bytes.Equal(pem, tls_pem) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", tls_pem, 0644)
		t.Fatal("invalid public key pem bytes")
	}

	loaded_pubkey_from_pem, err := LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	loaded_pubkey_from_der, err := LoadPublicKeyFromDER(der)
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_pem, err := loaded_pubkey_from_pem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_der, err := loaded_pubkey_from_der.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(new_der_from_der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	if !bytes.Equal(new_der_from_pem, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_pem)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}
}
