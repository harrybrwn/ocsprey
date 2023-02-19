#!/bin/sh

set -eu

export OCSP_URL=http://localhost:8888

for i in $(seq 0 1); do
	root="testdata/pki${i}"
	export CA_ROOT="${root}"

  # root="testdata/pki"
  rm -rf "${root}"
  mkdir -p "${root}/out" "${root}/db/certs"

  export OPENSSL_CONF=testdata/openssl.cnf
  GEN_LOG="/dev/null"
  # rm -f "$GEN_LOG"
  # touch "$GEN_LOG"

  if [ ! -f "${root}/db/serial" ]; then
  	echo '1000' > "${root}/db/serial"
  fi
  # CA
  touch "${root}/db/index.txt"
  openssl genrsa -out "${root}/ca.key" 2048 2>&1 >> "$GEN_LOG" 2>&1
  openssl req -new -x509 -subj '/CN=test ca' -extensions v3_ca -out "${root}/ca.crt" -key "${root}/ca.key" -nodes 2>&1 >> "$GEN_LOG" 2>&1

  out="${root}/out"

  # Server
  openssl genrsa -out "${out}/server.key" 2048 2>&1 >> "$GEN_LOG" 2>&1
  openssl req -new -subj '/CN=server' -key "${out}/server.key" -out "${out}/server.csr" -nodes 2>&1 >> "$GEN_LOG" 2>&1
  openssl ca -batch -extensions server -in "${out}/server.csr" -out "${out}/server.crt" 2>&1 >> "$GEN_LOG" 2>&1

  names="revoked one two three four five"
  for name in $names; do
  	openssl genrsa -out "${out}/${name}.key" 2048 >> "$GEN_LOG" 2>&1
  	openssl req -new -subj "/CN=${name}/OU=Tests" -key "${out}/${name}.key" -out "${out}/${name}.csr" -nodes >> "$GEN_LOG" 2>&1
  	openssl ca -batch -in "${out}/${name}.csr" -out "${out}/${name}.crt" >> "$GEN_LOG" 2>&1
  	rm "${out}/${name}.csr"
  done

  openssl genrsa -out "${out}/ocsp-responder.key" 2048 >> "$GEN_LOG" 2>&1
  openssl req -new -subj "/CN=ocsp-responder" -key "${out}/ocsp-responder.key" -out "${out}/ocsp-responder.csr" -nodes >> "$GEN_LOG" 2>&1
  openssl ca -batch -extensions v3_ocsp_responder -in "${out}/ocsp-responder.csr" -out "${out}/ocsp-responder.crt" >> "$GEN_LOG" 2>&1

  # Revoke one certificate for testing
  openssl ca -revoke "${out}/revoked.crt" >> "$GEN_LOG" 2>&1
done