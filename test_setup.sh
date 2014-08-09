#!/bin/bash

DEFAULT_KEYSIZE=1024
ENCRYPT_KEYS=" "

. ca_lib.sh




mkdir -p circle1
cp -r conf circle1/
cd circle1
export ORGA="Bieling"

echo
echo "====== Creating root client CA ======"
createCA "root-client"

echo
echo "====== Self-signing root client CA ======"
selfsignCA "root-client"

echo
echo "====== Creating CRL for root client CA ======"
createCRL "root-client"

echo
echo
echo

echo
echo "====== Creating bieling client CA ======"
createCA "client"

echo
echo "====== Signing bieling client CA with root client CA ======"
signCA "client" "root-client"

echo
echo "====== Creating CRL for bieling client CA ======"
createCRL "client"




echo
echo
echo

echo
echo "====== Creating email client key 'jakob' ======"
createClientKey "client" "jakob"

echo
echo "====== Signing email client certificate 'jakob' ======"
signCertificate "client" "jakob" "Jakob Bieling"

echo
echo
echo

echo
echo "====== Creating email client key 'john' ======"
createClientKey "client" "john"

echo
echo "====== Signing email client certificate 'john' ======"
signCertificate "client" "john" "John Bieling"



echo
echo
echo

echo
echo "====== Creating server key 'test.hazelnut4.nuts' ======"
echo "Note: Set the organisation name to the family name used for the client CA. Otherwise"
echo "the signing process will fail already."
createClientKey "server" "test.hazelnut4.nuts"

echo
echo "====== Signing webserver client certificate 'test.hazelnut4.nuts' with client CA ======"
echo "Note: Signing and letting apache use this certificate will work. But as soon as a"
echo "      client tries to verify it, it will fail."
echo
signCertificate "client" "test.hazelnut4.nuts"


echo
echo
echo
echo
echo "====== Creating second 'circle' ======"
echo "======================================"
cd -
mkdir -p circle2
cp -r conf circle2/
cd circle2
export ORGA="Second"

echo
echo
echo

echo
echo "====== Creating root client CA (second) ======"
createCA "root-client"

echo
echo "====== Self-signing root client CA (second) ======"
selfsignCA "root-client"

echo
echo "====== Creating CRL for root client CA (second) ======"
createCRL "root-client"

echo
echo
echo

echo
echo "====== Creating second client CA ======"
createCA "client"

echo
echo "====== Signing second client CA with root client CA ======"
signCA "client" "root-client"

echo
echo "====== Creating CRL for second client CA ======"
createCRL "client"

echo
echo
echo

echo
echo "====== Creating email client key 'rike' ======"
createClientKey "client" "rike"

echo
echo "====== Signing email client certificate 'rike' ======"
signCertificate "client" "rike" "Rike Second"




echo
echo
echo

echo
echo "====== Cross-sign circle1 and circle2 ======"
cd -

cp circle1/ca/client.csr circle2/ca/client_cirle1.csr
cd circle2
echo "====== Signing first circle CA with second circle CA"
signCA "client_cirle1" "root-client"
cd ..

cp circle2/ca/client.csr circle1/ca/client_circle2.csr
cd circle1
echo "====== Signing second circle CA with first circle CA"
signCA "client_circle2" "root-client"
cd ..

