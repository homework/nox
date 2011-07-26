#! /bin/sh -e

if [ $# -ne 1 ]; then
     echo 1>&2 Usage: $0 confdir
     exit 127
fi

if [ ! -e $1/noxca.cnf ]; then
     echo 1>&2 Directory $1/noxca.cnf doesnt exist
     exit 127
fi

#generate new ca key
if [ ! -d demoCA ]; then
    $1/CA.pl  -newca
fi

#generate new nox key and sign it
if [ ! -e noxca.crt ] || [ -e noxca.key ] ; then
    $1/CA.pl  -newreq-nodes -sign
    mv newcert.pem noxca.crt
    mv newkey.pem noxca.key
    rm newreq.pem
    $1/CA.pl -verify noxca.crt
fi

#save ca certification in order to verify client keys
cp demoCA/cacert.pem  ca.pem

#./CA.pl -newreq-nodes -sign -pkcs12
#mv newcert.pem client.crt
#mv newkey.pem client.key
#mv newcert.p12 client.p12
#cat client.key client.crt > client.pem

