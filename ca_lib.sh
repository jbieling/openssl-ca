#!/bin/bash


#! Set variables, if they have not been set yet
[ -z "$CNF_ROOT" ] && export CNF_ROOT=./conf
[ -z "$CA_ROOT"  ] && export CA_ROOT=./ca
[ -z "$CRL_ROOT" ] && export CRL_ROOT=./crl

[ -z "$CERT_ROOT"       ] && export CERT_ROOT=./cert
[ -z "$CA_KEYSIZE"      ] && export CA_KEYSIZE=4096
[ -z "$DEFAULT_KEYSIZE" ] && export DEFAULT_KEYSIZE=4096
[ -z "$DEFAULT_EXPIRY_YEARS" ] && export DEFAULT_EXPIRY_YEARS=2
[ -z "$ENCRYPT_KEYS"    ] && export ENCRYPT_KEYS=-aes256

[ -z "$START_DATE"    ] && START_DATE=
[ -z "$END_DATE"    ] && END_DATE=


echo ""
echo "Setting up ca_lib."
echo ""
echo "Please define ORGA before creating any certificate authorities. It is"
echo "used for the organisation field of all certificates."
echo ""
echo "You may specify the key size of certificates by defining CA_KEYSIZE and"
echo "and DEFAULT_KEYSIZE. The former sets the key size for certificates of"
echo "certificate authorities (currently $CA_KEYSIZE), the latter defines the"
echo "key size for client certificates (currently $DEFAULT_KEYSIZE). Note that"
echo "CA_KEYSIZE >= DEFAULT_KEYSIZE should hold (think 'weakest link')."
echo ""
echo "You may want to modify the CRL expiry fields in the CA configurations:"
echo "  default_crl_days  Specifies how long the certificate revocation list"
echo "                    is valid. The shorter, the more often you must"
echo "                    update. The longer, the more likely revocations will"
echo "                    slip through unnoticed at some point."
echo ""



# Prints all functions and their documentation.
function cahelp()
{
    local self="${BASH_SOURCE[0]}"

    if [[ $# -eq 1 ]]; then
        cat "$self" | tail -n +3 |
            sed -E '/^\{/,/^\}/d' |     # remove function bodies
            sed -E '/^(\[|\#\!)/d' |    # remove the variable section
            sed -nE '/./,/^$/p' |       # remove duplicate blank lines
            sed -nE "/^#/,/^$/{ H; /function $1/{g; p; q;}; /^$/x;};" |     # extract specific function
            sed -nE "/^function $1/d; /^$/d; s/^#([ ]?.*)$/  \1/;p"         # remove function head and hashes (#)
    else
        echo
        cat "$self" | tail -n +3 |
            sed -E '/^\{/,/^\}/d' |     # remove function bodies
            sed -E '/^(\[|\#\!)/d' |    # remove the variable section
            sed -nE '/./,/^$/p'         # remove duplicate blank lines
    fi

    echo
}


# Set the validity dates of the next certificate to be signed. The the dates
# are inclusive, meaning that the the validity starts at 0:00:00 and ends
# at 23:59:59.
#
# This function is automatically called before signing a client or CA
# certificate. It is not called for a self-signed root-certificate, for
# which the validity must be set in this script.
function setCertValidity()
{
    local firstLoop=1
    local inputStartDate=""
    local inputEndDate=""

    local inputStartYY=
    local inputStartMM=
    local inputStartDD=

    while [[ ! "${START_DATE}" =~ ^([0-9][0-9])(0[0-9]|1[012])([012][0-9]|3[01])$ || $firstLoop -eq 1 ]]; do
        firstLoop=0
        read -p "Not valid before (YYMMDD) [${START_DATE}]: " inputStartDate
        START_DATE=${inputStartDate:-$START_DATE}
    done

    inputStartYY=${BASH_REMATCH[1]}
    inputStartMM=${BASH_REMATCH[2]}
    inputStartDD=${BASH_REMATCH[3]}

    firstLoop=1
    while [[ ! "${END_DATE}" =~ ^([0-9][0-9])(0[0-9]|1[012])([012][0-9]|3[01])$ || $END_DATE -lt $START_DATE || $firstLoop -eq 1 ]]; do
        firstLoop=0
        END_DATE=$((inputStartYY+DEFAULT_EXPIRY_YEARS))
        END_DATE="$END_DATE$inputStartMM$inputStartDD"

        read -p "Not valid after (YYMMDD) [${END_DATE}]: " inputEndDate
        END_DATE=${inputEndDate:-$END_DATE}
    done
}


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
    local caName="$1"
    local caConf="$CNF_ROOT/ca.$caName.conf"
    local outFile="$CA_ROOT/$caName/private/$caName.key"

    if [[ $# -ne 1 ]]; then
        echo "Usage: ${FUNCNAME[0]} caName"
        echo ""
        cahelp createCA
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: private key file for CA '$caName' already exists"
        return 1
    fi

    # Create directories
    mkdir -p "$CA_ROOT/$caName/private" "$CA_ROOT/$caName/db"
    chmod 700 "$CA_ROOT/$caName/private"


    # Create database
    cp /dev/null "$CA_ROOT/$caName/db/$caName.db"
    cp /dev/null "$CA_ROOT/$caName/db/$caName.db.attr"
    echo 01 > "$CA_ROOT/$caName/db/$caName.crt.srl"
    echo 01 > "$CA_ROOT/$caName/db/$caName.crl.srl"

    # Create CA request
    openssl req -new -config "$caConf" -out "$CA_ROOT/$caName.csr" -keyout "$outFile"
}


# Sign an existing CA certificate with its own private key. The signed
# certificate is placed directly under ca/. If the certificate already
# exists, the process will be aborted.
#
# The signed certificate will be valid for 10 years (3650 days).
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
    local caName="$1"
    local caConf="$CNF_ROOT/ca.$caName.conf"
    local outFile="$CA_ROOT/$caName.crt"

    if [[ $# -ne 1 ]]; then
        echo "Usage: ${FUNCNAME[0]} caName"
        echo ""
        cahelp selfsignCA
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: certificate file for CA '$caName' already exists"
        return 1
    elif [[ ! -f "$CA_ROOT/$caName.csr" ]]; then
        echo "Error: certificate signing request for CA '$caName' does not exist"
        return 1
    fi

    # Create CA certificate
    openssl ca -selfsign -config "$caConf" -in "$CA_ROOT/$caName.csr" -out "$outFile" -extensions root_ca_ext -days 3650

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not created"
        rm -f "$outFile"
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
    local caName="$1"
    local parentCaName="$2"
    local parentCaConf="$CNF_ROOT/ca.$parentCaName.conf"
    local outFile="$CA_ROOT/$caName.crt"
    local outChainFile="$CA_ROOT/$caName-chain.crt"

    if [[ $# -ne 2 ]]; then
        echo "Usage: ${FUNCNAME[0]} caName parentCaName"
        echo ""
        cahelp signCA
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$parentCaConf" ]]; then
        echo "Error: the CA configuration '$parentCaConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: certificate file for CA '$caName' already exists"
        return 1
    elif [[ -f "$outChainFile" ]]; then
        echo "Error: certificate chain file for CA '$caName' already exists"
        return 1
    elif [[ ! -f "$CA_ROOT/$caName.csr" ]]; then
        echo "Error: certificate signing request for CA '$caName' does not exist"
        return 1
    fi

    setCertValidity

    # Create CA certificate
    openssl ca -config "$parentCaConf" -in "$CA_ROOT/$caName.csr" -out "$outFile" -extensions signing_ca_ext -startdate "${START_DATE}000000Z" -enddate "${END_DATE}235959Z"

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not signed"
        rm -f "$outFile"
        return 1
    fi

    # Create PEM bundle
    cat "$outFile" "$CA_ROOT/$parentCaName.crt" > "$outChainFile"
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
    local caName="$1"
    local caConf="$CNF_ROOT/ca.$caName.conf"
    local outFile="$CRL_ROOT/$caName.crl"

    if [[ $# -ne 1 ]]; then
        echo "Usage: ${FUNCNAME[0]} caName"
        echo ""
        cahelp createCRL
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: certificate revocation list for CA '$caName' already exists"
        return 1
    fi

    mkdir -p "$CRL_ROOT"

    # Create initial CRL
    openssl ca -gencrl -config "$caConf" -out "$outFile"
}



# Create a new client key including a certificate signing request.
#
# For creating a proper signing request, this function expects an
# OpenSSL configuration file (of the CA to be used for signing) to
# exist with the name conf/req.[caName].conf
#
# @param certName The name of the private key to be created. Note
#                 that this specifies the file name. The name of the
#                 owner as well as additional information will be
#                 querried by OpenSSL on the command line.
# @param caName   The name of the CA to be used for signing later.
#
function createClientKey()
{
    local certName="$1"
    local caName="$2"
    local caConf="$CNF_ROOT/req.$caName.conf"
    local outKey="$CERT_ROOT/$certName.pem"
    local outCsr="$CERT_ROOT/$certName.csr"

    if [[ $# -ne 2 ]]; then
        echo "Usage: ${FUNCNAME[0]} certName caName"
        echo ""
        cahelp createClientKey
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: client key '$certName' already exists"
        return 1
    fi

    mkdir -p "$CERT_ROOT"

    openssl genrsa $ENCRYPT_KEYS -out "$outKey" $DEFAULT_KEYSIZE

    openssl req -new -config "$caConf" -key "$outKey" -out "$outCsr"
}


# Sign an existing client key using a specified CA. If any certificates
# or certificate bundles already exist, the process will be aborted.
#
# This function expects an OpenSSL configuration file (of the CA to be
# used for signing) to exist with the name conf/ca.[caName].conf
#
# @param certName The name of the certificate signing request (without
#                 extension)
# @param name     The name of the owner to create the certificate for.
# @param caName   The name of the CA to be used for signing.
#
function signCertificate()
{
    local certName="$1"
    local name="$2"
    local caName="$3"
    local caConf="$CNF_ROOT/ca.$caName.conf"
    local outFile="$CERT_ROOT/$certName.crt"
    local outPEMBundleFile="$CERT_ROOT/$certName.key+crt"

    if [[ $# -ne 3 ]]; then
        echo "Usage: ${FUNCNAME[0]} certName name caName"
        echo ""
        cahelp signCertificate
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ -f "$outFile" ]]; then
        echo "Error: client certificate '$certName' already exists"
        return 1
    elif [[ -f "$outPEMBundleFile" ]]; then
        echo "Error: client certificate PEM bundle '$certName' already exists"
        return 1
    elif [[ ! -f "$CERT_ROOT/$certName.csr" ]]; then
        echo "Error: certificate signing request for '$certName' does not exist"
        return 1
    elif [[ ! -f "$CERT_ROOT/$certName.pem" ]]; then
        echo "Warning: private key for '$certName' does not exist, bundle will not be created"
    fi

    setCertValidity

    # Create certificate
    openssl ca -config "$caConf" -in "$CERT_ROOT/$certName.csr" -out "$outFile" -extensions ${caName}_ext -startdate "${START_DATE}000000Z" -enddate "${END_DATE}235959Z"

    if [[ ! -s "$outFile" ]]; then
        # File is zero-sized!
        echo "Error: certificate file not signed"
        rm -f "$outFile"
        return 1
    fi

    if [[ -f "$CERT_ROOT/$certName.pem" ]]; then
        # Create PEM bundle
        cat "$CERT_ROOT/$certName.pem" "$outFile" > "$outPEMBundleFile"
    fi

    echo ""
    echo "Creating a PKCS#12 bundle now. This will prompt for the password for the"
    echo "private key. If that is not desired or the private key is not available,"
    echo "you may exit the process by pressing Ctrl+C."
    echo "To create the PKCS#12 bundle at a later time, run"
    echo "  createPKCS12 $certName $caName"
    echo ""

    createPKCS12 $certName $caName
}


# Create a PKCS#12 certificate bundle containing the certificate and
# private key (you will need to enter the password for the key).
#
# This function expects an OpenSSL configuration file (of the CA to be
# used for signing) to exist with the name conf/ca.[caName].conf
#
# @param certName The name of the certificate
# @param caName   The name of the certificate authority. This is needed
#                 to attach the authority certificates to the PKCS#12
#                 bundle. This is optional, but highly recommended.
function createPKCS12()
{
    local certName="$1"
    local caName="$2"
    local certFile="$CERT_ROOT/$certName.crt"
    local certKey="$CERT_ROOT/$certName.pem"
    local caCertChain="$CA_ROOT/$caName-chain.crt"
    local outPKCSBundleFile="$CERT_ROOT/$certName.p12"

    if [[ $# -ne 1 && $# -ne 2 ]]; then
        echo "Usage: ${FUNCNAME[0]} certName [caName]"
        echo ""
        cahelp createPKCS12
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ -f "$outPKCSBundleFile" ]]; then
        echo "Error: client certificate PKCS#12 bundle '$certName' already exists"
        return 1
    elif [[ ! -f "$certFile" ]]; then
        echo "Error: certificate for '$certName' does not exist"
        return 1
    elif [[ ! -f "$certKey" ]]; then
        echo "Error: private key for '$certName' does not exist"
        return 1
    elif [[ ! -f "$caCertChain" ]]; then
        echo "Warning: certificate chain for the ca does not exist, skipping"
    fi

    # Create PKCS#12 bundle
    if [[ -f "$caCertChain" ]]; then
        openssl pkcs12 -export -inkey "$certKey" -in "$certFile" -certfile "$CA_ROOT/$caName-chain.crt" -out "$outPKCSBundleFile" -name "$name"
    else
        openssl pkcs12 -export -inkey "$certKey" -in "$certFile" -out "$outPKCSBundleFile" -name "$name"
    fi
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
    local caName="$1"
    local caConf="$CNF_ROOT/ca.$caName.conf"
    local certNumber="$2"

    if [[ $# -ne 2 ]]; then
        echo "Usage: ${FUNCNAME[0]} caName certNumber"
        echo ""
        cahelp revokeCertificate
        echo "Run 'cahelp' for a documentation on all available functions"
        return 1
    elif [[ ! -f "$caConf" ]]; then
        echo "Error: the CA configuration '$caConf' does not exist"
        return 1
    elif [[ ! -f "$CA_ROOT/$caName/$certNumber.pem" ]]; then
        echo "Error: certificate number '$certNumber' does not exist"
        return 1
    fi

    # Revoke certificate
    openssl ca -config "$caConf" -revoke "$CA_ROOT/$caName/$certNumber.pem" -crl_reason keyCompromise

    # Create CRL
    openssl ca -gencrl -config "$caConf" -out "$CRL_ROOT/$caName.crl"
}
