#! /bin/sh -e

if [ $# -ne 1 ]; then
    echo 1>&2 Usage: $0 confdir
    exit 127
fi

if [ ! -e $1/noxca.cnf ]; then
    echo 1>&2 Directory $1/noxca.cnf doesnt exist
    exit 127
fi

$1/CA.pl -newreq-nodes -sign -pkcs12
mv newcert.pem client.crt
mv newkey.pem client.key
mv newcert.p12 client.p12
cat client.key client.crt > client.pem
rm client.key client.crt

#
##Generate a new unencrypted rsa private key in PEM format
#openssl genrsa -out client.key 2048
#     
##Create a certificate signing request (CSR) using your rsa private key
#openssl req -new  -config $1/noxca.cnf -key client.key -out client.csr
#
##Self-sign your CSR with your own private key
#openssl x509 -req -days 365 -in client.csr -CA noxca.cert -CAkey \
#    noxca.key -set_serial 01 -out client.crt
#
## generate a pkcs12 key
#openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt
#cat client.key client.crt > client.pem
#
#rm client.key client.csr client.crt
