Info about the pem files
========================

Information about the start and expiry date is listed below.


ca-cert-one-cert.pem
 Not Before: Jan  5 16:01:28 2021 GMT
 Not After : Jan  3 16:01:28 2031 GMT

ca-cert-two-certs.pem
 Not Before: Jan  5 16:01:28 2021 GMT
 Not After : Jan  3 16:01:28 2031 GMT

cert-with-key-CNdifferSAN.pem
 Not Before: Jul 22 20:19:01 2019 GMT
 Not After : Jul 19 20:19:01 2029 GMT

cert-with-key-CNnoSAN.pem
 Not Before: Jul 30 16:44:40 2019 GMT
 Not After : Jul 27 16:44:40 2029 GMT

cert-with-key-invalidDNS.pem
 Not Before: Jul 22 16:24:35 2019 GMT
 Not After : Jul 19 16:24:35 2029 GMT

cert-with-key-multiSAN.pem
 Not Before: Jul 22 19:26:43 2019 GMT
 Not After : Jul 19 19:26:43 2029 GMT

cert-with-key-SAN.pem
 Not Before: Mar 19 15:44:14 2019 GMT
 Not After : Mar 16 15:44:14 2029 GMT

docker_registry-cert-2xcert-1xkey-with-key.pem
 Not Before: Jan  4 14:54:18 2021 GMT
 Not After : Jan  2 14:54:18 2031 GMT

docker_registry-cert-2xcert-1xkey-with-key-wrong-order.pem
 Not Before: Jan  5 16:01:28 2021 GMT
 Not After : Jan  3 16:01:28 2031 GMT

ssl-cert-2xcert-1xkey-with-key.pem
 Not Before: Jan  4 14:54:18 2021 GMT
 Not After : Jan  2 14:54:18 2031 GMT

ssl-cert-2xcert-1xkey-with-key-wrong-order.pem
 Not Before: Jan  5 16:01:28 2021 GMT
 Not After : Jan  3 16:01:28 2031 GMT


========================

Information about how to update or recreate these files.

The certificate pem files were created using cert-manager and creating a chain
of CAs.
Root CA -> Intermediate CA -> Endpoint CA

Create manifest files similar to ones show below.


===
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: example-self-signing-issuer
spec:
  selfSigned: {}
===
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: example-rootca-issuer
spec:
  ca:
    secretName: example-rootca-certificate
===
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: example-rootca-certificate
spec:
  secretName: example-rootca-certificate
  duration: 87600h # 3650d
  renewBefore: 360h # 15d
  commonName: "example-rootca"
  isCA: true
  issuerRef:
    name: example-self-signing-issuer
    kind: Issuer
===

Create similar files for IntermediateCA & EndpointCA. Then, perform 'kubectl apply'.

Once applied, grab the data ca.crt, tls.crt & tls.key from each level's secret.

  NAME=example-rootca-certificate

  CERT64=`kubectl get secret ${NAME} -n example-certs -o yaml | fgrep ca.crt | fgrep -v "f:ca.crt" | awk '{print $2}'`
  echo $CERT64 | base64 --decode > example-certs/${NAME}.ca.crt.pem

  CERT64=`kubectl get secret ${NAME} -n example-certs -o yaml | fgrep tls.crt | fgrep -v "f:tls.crt" | awk '{print $2}'`
  echo $CERT64 | base64 --decode > example-certs/${NAME}.tls.crt.pem
  if [ $VERBOSE -eq 1 ]
  then
    echo
    openssl x509 -in example-certs/${NAME}.tls.crt.pem -noout -text
    echo
  fi

  CERT64=`kubectl get secret ${NAME} -n example-certs -o yaml | fgrep tls.key | fgrep -v "f:tls.key" | awk '{print $2}'`
  echo $CERT64 | base64 --decode > example-certs/${NAME}.tls.key.pem

The generated pem files can then be used to update the files used here.
