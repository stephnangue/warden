
# test operations with root token

export WARDEN_TOKEN=cws.L8pq77ULu_0H-vybk4Lnj8q7XqKe1WTgB3_f6YMn3jeXMl7LJNIS8abHlayjOWrF

# test namespace management 

./warden namespace list
./warden namespace create test
./warden namespace read test
./warden namespace update test --metadata=env=dev --metadata=team=devops
./warden namespace delete test -f

./warden write sys/namespaces/child
./warden list sys/namespaces
./warden read sys/namespaces/child
./warden write sys/namespaces/child custom_metadata='{"env":"dev","team":"devops"}'
./warden delete sys/namespaces/child -f

# test policy management

./warden policy write auth-admin - <<EOF
path "sys/auth/*" {
  capabilities = ["read", "delete", "create", "update", "sudo"]
}

path "sys/auth" {
  capabilities = ["list"]
}
EOF
./warden policy write auth-reader - <<EOF
    path "sys/auth" {
        capabilities = ["list"]
    }
EOF
./warden policy write admin-policy - <<EOF
path "sys/auth/*" {
  capabilities = ["read", "delete", "create", "update", "sudo"]
}
path "sys/auth" {
  capabilities = ["list"]
}
path "auth/*" {
  capabilities = ["read", "delete", "create", "update"]
}
path "sys/namespaces/*" {
  capabilities = ["read", "delete", "create", "update"]
}
path "sys/namespaces" {
  capabilities = ["list"]
}
path "sys/providers/*" {
  capabilities = ["read", "delete", "create", "update"]
}
path "sys/providers" {
  capabilities = ["list"]
}
path "aws/config" {
  capabilities = ["read", "delete", "create", "update", "list"]
}
path "sys/cred/*" {
  capabilities = ["read", "delete", "create", "update", "list", "sudo"]
}
path "sys/policies/*" {
  capabilities = ["read", "delete", "create", "update", "list"]
}
EOF
./warden policy write reader-policy - <<EOF
path "sys/auth/*" {
  capabilities = ["read", "sudo"]
}
path "sys/auth" {
  capabilities = ["list"]
}
path "sys/providers/*" {
  capabilities = ["read"]
}
path "sys/providers" {
  capabilities = ["list"]
}
path "sys/cred/*" {
  capabilities = ["read", "list", "sudo"]
}
path "sys/policy/*" {
  capabilities = ["read", "list"]
}
EOF
./warden policy write aws-streaming - <<EOF
path "aws/gateway*" {
  capabilities = ["stream"]
}
EOF
./warden policy list
./warden policy read auth-admin
./warden policy delete auth-admin -f

# test credential source management

./warden cred source create vault \
  --type hvault \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=c0ae884e-b55e-1736-3710-bb1d88d76182 \
  --config secret_id=e0b8f9b8-6b32-5478-9a73-196e50734c2f \
  --config approle_mount=warden_approle 
./warden cred source list
./warden cred source read vault
./warden cred source update vault --config secret_id=e0b8f9b8-6b32-5478-9a73-196e50734c2f
./warden cred source delete -f

# test credential spec management

./warden cred spec create aws_local \
  --type aws_access_keys \
  --source local \
  --config access_key_id=test \
  --config secret_access_key=test
./warden cred spec create aws_static \
  --type aws_access_keys \
  --source vault \
  --config mint_method=kv2_static \
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod
./warden cred spec create aws_dynamic \
  --type aws_access_keys \
  --source vault \
  --config mint_method=dynamic_aws \
  --config aws_mount=aws \
  --config role_name=terraform \
  --config ttl=900s \
  --config role_session_name=warden \
  --config role_arn=arn:aws:iam::905418489750:role/terraform-role-warden \
  --min-ttl 600s \
  --max-ttl 8h
./warden cred spec read aws_test
./warden cred spec list
./warden cred spec delete aws_test -f
./warden cred spec update aws_local \
  --config access_key_id=test123
./warden cred spec update aws_dynamic \
  --max-ttl 8h

# test auth methods managment

./warden auth enable --type=jwt --description="jwt test auth method"
./warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json
./warden read auth/jwt/config
./warden auth enable --type=jwt test-jwt --description="test auth method"
./warden write auth/test-jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json
./warden read auth/test-jwt/config
./warden auth disable test-jwt

./warden write auth/jwt/role/admin \
    token_type=warden_token \
    token_policies="admin-policy,auth-admin" \
    user_claim=sub \
    bound_claims='{"iss":"http://localhost:4444"}' \
    token_ttl=2h
./warden write auth/jwt/role/reader \
    token_policies="reader-policy" \
    user_claim=sub \
    bound_claims='{"iss":"http://localhost:4444"}' \
    token_ttl=1h
./warden write auth/jwt/role/aws-streamer \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_local \
    token_ttl=1h
./warden write auth/jwt/role/aws-kv \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_static \
    token_ttl=1h
./warden write auth/jwt/role/aws-dynamic \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_dynamic \
    token_ttl=1h
./warden list auth/jwt/role
./warden read auth/jwt/role/admin
./warden read auth/jwt/role/reader
./warden delete auth/jwt/role/reader -f

# test providers management

./warden provider list
./warden provider enable --type=aws --description="aws provider"
./warden provider read aws
./warden write aws/config proxy_domains="localhost,warden"
./warden read aws/config
./warden provider disable aws

# test legacy streaming 

# test transparent streaming 

# test operation with non root token

export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=service-client-1&client_secret=service-secret-1-change-this&scope=api:read api:write' \
  | jq -r '.access_token')
LOGIN_OUTPUT=$(./warden login --method=jwt --token=$JWT --role=aws-kv)
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')
export AWS_ENDPOINT_URL=http://localhost:5000/v1/aws/gateway

# test in chid namespace

./warden namespace create PROD
./warden namespace create SEC -n PROD
./warden -n PROD/SEC policy write aws-streaming - <<EOF
path "aws/gateway*" {
  capabilities = ["stream"]
}
EOF
./warden -n PROD/SEC cred source create vault \
  --type hvault \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=c0ae884e-b55e-1736-3710-bb1d88d76182 \
  --config secret_id=e0b8f9b8-6b32-5478-9a73-196e50734c2f \
  --config approle_mount=warden_approle

./warden -n PROD/SEC cred spec create aws_local \
  --type aws_access_keys \
  --source local \
  --config access_key_id=test \
  --config secret_access_key=test
./warden -n PROD/SEC cred spec create aws_static \
  --type aws_access_keys \
  --source vault \
  --config mint_method=kv2_static \
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod
./warden -n PROD/SEC cred spec create aws_dynamic \
  --type aws_access_keys \
  --source vault \
  --config mint_method=dynamic_aws \
  --config aws_mount=aws \
  --config role_name=terraform \
  --config ttl=900s \
  --config role_session_name=warden \
  --config role_arn=arn:aws:iam::905418489750:role/terraform-role-warden \
  --min-ttl 600s \
  --max-ttl 8h

./warden -n PROD/SEC auth enable --type=jwt --description="jwt test auth method"
./warden -n PROD/SEC write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

./warden -n PROD/SEC write auth/jwt/role/aws-streamer \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_local \
    token_ttl=1h
./warden -n PROD/SEC write auth/jwt/role/aws-kv \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_static \
    token_ttl=1h

./warden -n PROD/SEC provider enable --type=aws --description="aws provider"
./warden -n PROD/SEC write aws/config proxy_domains="localhost,warden"

export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=service-client-1&client_secret=service-secret-1-change-this&scope=api:read api:write' \
  | jq -r '.access_token')
LOGIN_OUTPUT=$(./warden -n PROD/SEC login --method=jwt --token=$JWT --role=aws-kv)
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')
export AWS_ENDPOINT_URL=http://localhost:5000/v1/PROD/SEC/aws/gateway

# test vault streaming

./warden -n PROD/SEC policy write vault-streaming - <<EOF
path "+/gateway*" {
  capabilities = ["stream"]
}
path "+/role/+/gateway*" {
  capabilities = ["stream"]
}
EOF

./warden -n PROD/SEC cred spec create vault_reader \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=reader \
  --min-ttl 600s \
  --max-ttl 2h

./warden -n PROD/SEC write auth/jwt/role/vault-reader \
    token_type=warden_token \
    token_policies="vault-streaming" \
    user_claim=sub \
    cred_spec_name=vault_reader \
    token_ttl=1h

./warden -n PROD/SEC cred spec create full_access \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=full-access \
  --min-ttl 600s \
  --max-ttl 2h

./warden -n PROD/SEC write auth/jwt/role/full-access \
    token_type=warden_token \
    token_policies="vault-streaming" \
    user_claim=sub \
    cred_spec_name=full_access \
    token_ttl=1h

./warden -n PROD/SEC cred spec create terraform \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=terraform-admin \
  --min-ttl 600s \
  --max-ttl 2h

./warden -n PROD/SEC write auth/jwt/role/terraform \
    token_type=warden_token \
    token_policies="vault-streaming" \
    user_claim=sub \
    cred_spec_name=ephemeral \
    token_ttl=1h

  ./warden -n PROD/SEC provider enable --type=vault --description="vault provider"
  ./warden -n PROD/SEC write vault/config vault_address="http://127.0.0.1:8200" tls_skip_verify=true

export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
LOGIN_OUTPUT=$(./warden -n PROD/SEC login --method=jwt --token=$JWT --role=terraform)
export VAULT_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*token=\([^ ]*\).*/\1/')
export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault/gateway

# test vault streaming in transparent mode

./warden -n PROD/SEC provider enable --type=vault --description="vault provider with transparent auth" vault-auto 
./warden -n PROD/SEC write vault-auto/config vault_address="http://127.0.0.1:8200" transparent_mode=true auto_auth_path=auth/jwt tls_skip_verify=true default_role=ephemeral

./warden -n PROD/SEC cred spec create provisionner \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=terraform-admin \
  --config ttl=15m \
  --min-ttl 600s \
  --max-ttl 1h

./warden -n PROD/SEC write auth/jwt/role/provisionner \
    token_type=jwt_role \
    token_policies="vault-streaming" \
    user_claim=sub \
    cred_spec_name=provisionner \
    token_ttl=1h

export VAULT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault-auto/role/provisionner/gateway


./warden -n PROD/SEC cred spec create ephemeral \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=ephemeral-admin \
  --config ttl=20m \
  --min-ttl 600s \
  --max-ttl 1h

./warden -n PROD/SEC write auth/jwt/role/ephemeral \
    token_type=jwt_role \
    token_policies="vault-streaming" \
    user_claim=sub \
    cred_spec_name=ephemeral

export VAULT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault-auto/role/ephemeral/gateway

export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault-auto/gateway

export VAULT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=gilab-job&client_secret=test@gilab-job&scope=api:read api:write' \
  | jq -r '.access_token')
export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault-auto/role/ephemeral/gateway

./warden namespace create DEV -n PROD

./warden -n PROD/DEV policy write streaming - <<EOF
path "+/gateway*" {
  capabilities = ["stream"]
}
path "+/role/+/gateway*" {
  capabilities = ["stream"]
}
EOF

./warden -n PROD/DEV auth enable --type=jwt --description="jwt test auth method"
./warden -n PROD/DEV write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

./warden -n PROD/DEV cred source create vault \
  --type hvault \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=tf-role-id-1234-5678-90ab-cdef12345678 \
  --config secret_id=tf-secret-id-abcd-efgh-ijkl-mnop12345678 \
  --config approle_mount=warden_approle

./warden -n PROD/DEV cred spec create provisionner \
  --type vault_token \
  --source vault \
  --config mint_method=vault_token \
  --config token_role=terraform-admin \
  --config ttl=15m \
  --min-ttl 600s \
  --max-ttl 1h

./warden -n PROD/DEV write auth/jwt/role/provisionner \
    token_type=jwt_role \
    token_policies="streaming" \
    user_claim=sub \
    cred_spec_name=provisionner \
    token_ttl=1h

./warden -n PROD/DEV provider enable --type=vault --description="vault provider with transparent auth" vault-auto 
./warden -n PROD/DEV write vault-auto/config vault_address="http://127.0.0.1:8200" transparent_mode=true auto_auth_path=auth/jwt tls_skip_verify=true default_role=provisioner

export VAULT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
export VAULT_ADDR=http://localhost:5000/v1/PROD/DEV/vault-auto/role/provisionner/gateway


./warden -n PROD/DEV cred spec create aws_local \
  --type aws_access_keys \
  --source local \
  --config access_key_id=AKIA5FTZFX6LC3IQNGPV \
  --config secret_access_key=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

./warden -n PROD/DEV cred spec create aws_static \
  --type aws_access_keys \
  --source vault \
  --config mint_method=kv2_static \
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod

./warden -n PROD/DEV write auth/jwt/role/aws-streamer \
    token_type=aws_access_keys \
    token_policies="streaming" \
    user_claim=sub \
    cred_spec_name=aws_local \
    token_ttl=1h
./warden -n PROD/DEV write auth/jwt/role/aws-kv \
    token_type=aws_access_keys \
    token_policies="streaming" \
    user_claim=sub \
    cred_spec_name=aws_static \
    token_ttl=1h

./warden -n PROD/DEV provider enable --type=aws --description="aws provider"
./warden -n PROD/DEV write aws/config proxy_domains="localhost,warden"

export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
LOGIN_OUTPUT=$(./warden -n PROD/DEV login --method=jwt --token=$JWT --role=aws-streamer)
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')
export AWS_ENDPOINT_URL=http://localhost:5000/v1/PROD/DEV/aws/gateway

./warden -n PROD/DEV cred source create vault-dev \
  --type hvault \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=cde5a2cd-9bb7-a75f-5d24-c524c3a0fe8e \
  --config secret_id=9fb4e44b-5005-0265-3414-0b4d1c2caf93 \
  --config secret_id_accessor=a2567bff-1b18-1086-732d-1d262a9bd6ee \
  --config approle_mount=warden_approle \
  --config role_name=source_role \
  --rotation-period 5m

./warden -n PROD/DEV cred spec create operator \
  --type vault_token \
  --source vault-dev \
  --config mint_method=vault_token \
  --config token_role=terraform-admin \
  --config ttl=15m \
  --min-ttl 600s \
  --max-ttl 1h

./warden -n PROD/DEV cred spec create performer \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::905418489750:role/devops-warden-role \
  --config ttl=15m \
  --min-ttl 600s \
  --max-ttl 1h

./warden -n PROD/DEV write auth/jwt/role/operator \
    token_type=jwt_role \
    token_policies="streaming" \
    user_claim=sub \
    cred_spec_name=operator \
    token_ttl=1h

export VAULT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
export VAULT_ADDR=http://localhost:5000/v1/PROD/DEV/vault-auto/role/operator/gateway


./warden -n PROD/DEV write auth/jwt/role/performer \
    token_type=aws_access_keys \
    token_policies="streaming" \
    user_claim=sub \
    cred_spec_name=performer \
    token_ttl=30m

export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=agent&client_secret=test@agent&scope=api:read api:write' \
  | jq -r '.access_token')
LOGIN_OUTPUT=$(./warden -n PROD/DEV login --method=jwt --token=$JWT --role=performer)
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')
export AWS_ENDPOINT_URL=http://localhost:5000/v1/PROD/DEV/aws/gateway