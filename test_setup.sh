#!/bin/bash

DEFAULT_KEYSIZE=1024
ENCRYPT_KEYS=" "

. ca_lib.sh




mkdir -p circle1
cp -r conf circle1/
cd circle1
export ORGA="Bieling"

echo
echo "====== Creating root mail CA ======"
createCA "root-email"

echo
echo "====== Self-signing root mail CA ======"
selfsignCA "root-email"

echo
echo "====== Creating CRL for root mail CA ======"
createCRL "root-email"

echo
echo
echo

echo
echo "====== Creating bieling mail CA ======"
createCA "email"

echo
echo "====== Signing bieling mail CA with root mail CA ======"
signCA "email" "root-email"

echo
echo "====== Creating CRL for bieling mail CA ======"
createCRL "email"




echo
echo
echo

echo
echo "====== Creating email client key 'jakob' ======"
createClientKey "email" "jakob"

echo
echo "====== Signing email client certificate 'jakob' ======"
signCertificate "email" "jakob" "Jakob Bieling"

echo
echo
echo

echo
echo "====== Creating email client key 'john' ======"
createClientKey "email" "john"

echo
echo "====== Signing email client certificate 'john' ======"
signCertificate "email" "john" "John Bieling"



echo
echo
echo

echo
echo "====== Creating web server key 'test.hazelnut4.nuts' ======"
createClientKey "web" "test.hazelnut4.nuts"

echo
echo "====== Signing webserver client certificate 'test.hazelnut4.nuts' with email CA ======"
echo "Note: Signing and letting apache use this certificate will work. But as soon as a"
echo "      client tries to verify it, it will fail."
echo
signCertificate "email" "test.hazelnut4.nuts"


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
echo "====== Creating root mail CA ======"
createCA "root-email"

echo
echo "====== Self-signing root mail CA ======"
selfsignCA "root-email"

echo
echo "====== Creating CRL for root mail CA ======"
createCRL "root-email"

echo
echo
echo

echo
echo "====== Creating second mail CA ======"
createCA "email"

echo
echo "====== Signing second mail CA with root mail CA ======"
signCA "email" "root-email"

echo
echo "====== Creating CRL for second mail CA ======"
createCRL "email"

echo
echo
echo

echo
echo "====== Creating email client key 'rike' ======"
createClientKey "email" "rike"

echo
echo "====== Signing email client certificate 'rike' ======"
signCertificate "email" "rike" "Rike Second"
