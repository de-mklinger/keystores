#!/bin/bash

set -eu

DIR=$(cd "$(dirname "$0")" && pwd)

(cd "$DIR" && rm *.p12 *.pem *.jks)

(cd "$DIR" && ./certs.py)

password="testpwd"

for pkcs12file in $(find "$DIR" -maxdepth 1 -name "*.p12"); do
	filename=$(basename -- "$pkcs12file")
	filename="${filename%.*}"

	jkspwdfile="$DIR/${filename}-with-password.jks"
	keytool \
		-importkeystore \
		-srckeystore $pkcs12file \
		-destkeystore $jkspwdfile \
		-srcstoretype PKCS12 \
		-deststoretype JKS \
		-srcstorepass "" \
		-deststorepass "$password" -v

	pkcs12pwdfile="$DIR/${filename}-with-password.p12"
	keytool \
		-importkeystore \
		-srckeystore $pkcs12file \
		-destkeystore $pkcs12pwdfile \
		-srcstoretype PKCS12 \
		-deststoretype PKCS12 \
		-srcstorepass "" \
		-deststorepass "$password" -v
done

cat "$DIR/server-cert.pem" "$DIR/ca-cert.pem" > "$DIR/server-and-ca-cert.pem"
 
