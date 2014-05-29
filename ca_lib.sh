#!/bin/bash


# Set variables, if they have not been set yet
[ -z "$CNF_ROOT" ] && CNF_ROOT=./conf
[ -z "$CA_ROOT"  ] && CA_ROOT=./ca
[ -z "$CRL_ROOT" ] && CRL_ROOT=./crl

[ -z "$CERT_ROOT"       ] && CERT_ROOT=./cert
[ -z "$DEFAULT_KEYSIZE" ] && DEFAULT_KEYSIZE=4096
[ -z "$ENCRYPT_KEYS"    ] && ENCRYPT_KEYS=-aes256



# Create a new CA key and create the necessary database structure. If the
# CA key already exists, the process will be aborted.
#
# This function expects a OpenSSL configuration file to exist with the
# name conf/ca.[caName].conf.
#
# @param caName     The name of the new CA.
#
# \note The CA will reside in the directory ca/[caName]/, the private key
#       being in a subdirectory 'private', the database files being in a
#       subdirectory 'db'. The certificate signing request (and the final
#       certficate) is placed directly under ca/.
#
function createCA()
{
    local caName=$1
    local outFile=$CA_ROOT/$caName/private/$caName.key

    if [[ -f "$outFile" ]]; then
        echo "Error: private key file for CA '$caName' already exists"
        return 1
    fi

    # Create directories
    mkdir -p $CA_ROOT/$caName/private $CA_ROOT/$caName/db
    chmod 700 $CA_ROOT/$caName/private


    # Create database
    cp /dev/null $CA_ROOT/$caName/db/$caName.db
    cp /dev/null $CA_ROOT/$caName/db/$caName.db.attr
    echo 01 > $CA_ROOT/$caName/db/$caName.crt.srl
    echo 01 > $CA_ROOT/$caName/db/$caName.crl.srl


    # Create CA request
    openssl req -new -config $CNF_ROOT/ca.$caName.conf -out $CA_ROOT/$caName.csr -keyout "$outFile"
}

# Sign an existing CA certificate with its own private key. The signed
# certificate is placed directly under ca/. If the certificate already
# exists, the process will be aborted.
#
# This function expects a OpenSSL configuration file to exist with the
# name conf/ca.[caName].conf.
#
# @param caName     The name of the CA. The CA should reside in a
#                   directory ca/[caName]/ and its the private key in
#                   ca/[caName]/private.
#
function selfsignCA()
{
    local caName=$1
    local outFile=$CA_ROOT/$caName.crt

    if [[ -f "$outFile" ]]; then
        echo "Error: certificate file for CA '$caName' already exists"
        return 1
    fi

    # Create CA certificate
    openssl ca -selfsign -config $CNF_ROOT/ca.$caName.conf -in $CA_ROOT/$caName.csr -out "$outFile" -extensions root_ca_ext -days 3650

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not created"
        rm -r "$outFile"
        return 1
    fi
}

# Sign an existing CA certificate with the private private key of another CA.
# The signed certificate is placed directly under ca/. If the certificate
# already exists, the process will be aborted.
#
# This function expects a OpenSSL configuration file for the signing CA (i.e.
# 'parentCaName') to exist with the name conf/ca.[parentCaName].conf.
#
# @param caName       The name of the CA to be signed. The CA should reside in
#                     a directory ca/[caName]/.
# @param parentCaName The name of the CA to be used for signing. The CA should
#                     reside in a directory ca/[caName]/ and its the private key
#                     in ca/[caName]/private.
#
function signCA()
{
    local caName=$1
    local parentCaName=$2
    local outFile=$CA_ROOT/$caName.crt
    local outChainFile=$CA_ROOT/$caName-chain.crt

    if [[ -f "$outFile" ]]; then
        echo "Error: certificate file for CA '$caName' already exists"
        return 1
    fi

    if [[ -f "$outChainFile" ]]; then
        echo "Error: certificate chain file for CA '$caName' already exists"
        return 1
    fi

    # Create CA certificate
    openssl ca -config $CNF_ROOT/ca.$parentCaName.conf -in $CA_ROOT/$caName.csr -out "$outFile" -extensions signing_ca_ext

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not signed"
        rm -r "$outFile"
        return 1
    fi

    # Create PEM bundle
    cat $outFile $CA_ROOT/$parentCaName.crt > $outChainFile
}



# Create the initial certificate revokation list (CRL) for a given CA. If the
# CRL already exists, the process will be aborted.
#
# This function expects a OpenSSL configuration file to exist with the
# name conf/ca.[caName].conf.
#
# @param caName The name of the CA to create the CRL for. The CRLs for all CA
#               will be placed in the directory crl/.
#
function createCRL()
{
    local caName=$1
    local outFile=$CRL_ROOT/$caName.crl

    if [[ -f "$outFile" ]]; then
        echo "Error: certificate revocation list for CA '$caName' already exists"
        return 1
    fi

    mkdir -p $CRL_ROOT

    # Create initial CRL
    openssl ca -gencrl -config $CNF_ROOT/ca.$caName.conf -out "$outFile"
}



# Create a new client key including a certificate signing request.
#
# For creating a proper signing request, this function expects an
# OpenSSL configuration file (of the CA to be used for signing) to
# exist with the name conf/req.[caName].conf
#
# @param caName   The name of the CA to be used for signing later.
# @param certName The name of the private key to be created. Note
#                 that this specifies the file name. The name of the
#                 owner as well as additional information will be
#                 querried by OpenSSL on the command line.
#
function createClientKey()
{
    local caName=$1
    local certName=$2
    local outFile=$CERT_ROOT/$certName.pem

    if [[ -f "$outFile" ]]; then
        echo "Error: client key '$certName' already exists"
        return 1
    fi

    mkdir -p $CERT_ROOT

    openssl genrsa $ENCRYPT_KEYS -out "$outFile" $DEFAULT_KEYSIZE

    openssl req -new -config $CNF_ROOT/req.$caName.conf -key $CERT_ROOT/$certName.pem -out $CERT_ROOT/$certName.csr
}

# Sign an existing client key using a specified CA.
#
# This function expects an OpenSSL configuration file (of the CA to be
# used for signing) to exist with the name conf/ca.[caName].conf
#
# @param caName   The name of the CA to be used for signing.
# @param certName The name of the certificate signing request (without
#                 extension)
# @param name     The name of the owner to create the certificate for.
#
function signCertificate()
{
    local caName=$1
    local certName=$2
    local name=$3
    local outFile=$CERT_ROOT/$certName.crt
    local outPKCSBundleFile=$CERT_ROOT/$certName.p12
    local outPEMBundleFile=$CERT_ROOT/$certName.key+crt

    if [[ -f "$outFile" ]]; then
        echo "Error: client certificate '$certName' already exists"
        return 1
    fi

    if [[ -f "$outPKCSBundleFile" ]]; then
        echo "Error: client certificate PKCS#12 bundle '$certName' already exists"
        return 1
    fi

    if [[ -f "$outPEMBundleFile" ]]; then
        echo "Error: client certificate PEM bundle '$certName' already exists"
        return 1
    fi

    # Create certificate
    openssl ca -config $CNF_ROOT/ca.$caName.conf -in $CERT_ROOT/$certName.csr -out "$outFile" -extensions ${caName}_ext

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not signed"
        rm -r "$outFile"
        return 1
    fi

    # Create PKCS#12 bundle
    openssl pkcs12 -export -inkey $CERT_ROOT/$certName.pem -in $CERT_ROOT/$certName.crt -certfile $CA_ROOT/$caName-chain.crt -out $outPKCSBundleFile -name "$name"

    # Create PEM bundle
    cat $CERT_ROOT/$certName.pem $outFile > $outPEMBundleFile
}

# Revoke an existing client certificate that was previously signed by a
# CA.
#
# This function expects an OpenSSL configuration file (of the CA that
# was used for signing, i.e. the CA to be used for revoking) to exist
# with the name conf/ca.[caName].conf
#
# @param caName     The name of the CA to be used for signing.
# @param certNumber The *number* of the certificate request (without
#                   extension)
#
function revokeCertificate()
{
    local caName=$1
    local certNumber=$2

    # Revoke certificate
    openssl ca -config $CNF_ROOT/ca.$caName.conf -revoke $CA_ROOT/$caName/$certNumber.pem -crl_reason keyCompromise

    # Create CRL
    openssl ca -gencrl -config $CNF_ROOT/ca.$caName.conf -out $CRL_ROOT/$caName.crl
}
