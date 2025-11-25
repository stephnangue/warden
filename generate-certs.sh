#!/bin/bash

# Script to generate self-signed TLS certificates for the stack

set -e

echo "Generating TLS certificates..."

# Create certificate directories
mkdir -p certs/{vault,mysql,warden}

# Generate CA certificate
echo "Generating CA certificate..."
openssl genrsa -out certs/ca-key.pem 4096
openssl req -new -x509 -days 365 -key certs/ca-key.pem -out certs/ca.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=Root CA"

# Generate Vault certificates
echo "Generating Vault certificates..."
openssl genrsa -out certs/vault/vault-key.pem 4096
openssl req -new -key certs/vault/vault-key.pem -out certs/vault/vault.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault"

cat > certs/vault/vault-ext.cnf <<EOF
subjectAltName = DNS:vault,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days 365 -in certs/vault/vault.csr \
  -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
  -out certs/vault/vault-cert.pem -extfile certs/vault/vault-ext.cnf

cp certs/ca.pem certs/vault/ca.pem

# Generate MySQL server certificates
echo "Generating MySQL server certificates..."
openssl genrsa -out certs/mysql/server-key.pem 4096
openssl req -new -key certs/mysql/server-key.pem -out certs/mysql/server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=mysql-server"

cat > certs/mysql/mysql-ext.cnf <<EOF
subjectAltName = DNS:mysql-server,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days 365 -in certs/mysql/server.csr \
  -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
  -out certs/mysql/server-cert.pem -extfile certs/mysql/mysql-ext.cnf

# Generate MySQL client certificates
echo "Generating MySQL client certificates..."
openssl genrsa -out certs/mysql/client-key.pem 4096
openssl req -new -key certs/mysql/client-key.pem -out certs/mysql/client.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=mysql-client"

cat > certs/mysql/client-ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 365 -in certs/mysql/client.csr \
  -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
  -out certs/mysql/client-cert.pem -extfile certs/mysql/client-ext.cnf

cp certs/ca.pem certs/mysql/ca.pem

# Generate Warden certificates
echo "Generating Warden certificates..."
openssl genrsa -out certs/warden/warden-key.pem 4096
openssl req -new -key certs/warden/warden-key.pem -out certs/warden/warden.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=warden"

cat > certs/warden/warden-ext.cnf <<EOF
subjectAltName = DNS:warden,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth,clientAuth
EOF

openssl x509 -req -days 365 -in certs/warden/warden.csr \
  -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
  -out certs/warden/warden-cert.pem -extfile certs/warden/warden-ext.cnf

cp certs/ca.pem certs/warden/ca.pem

# Set proper permissions
chmod 644 certs/**/*.pem
chmod 600 certs/**/*-key.pem
chmod 600 certs/ca-key.pem

echo "Certificates generated successfully!"
echo ""
echo "Certificate locations:"
echo "  CA: certs/ca.pem"
echo "  Vault: certs/vault/"
echo "  MySQL: certs/mysql/"
echo "  Warden: certs/warden/"