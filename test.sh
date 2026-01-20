
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
  --type hashicorp_vault \
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
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod
./warden cred spec create aws_dynamic \
  --type aws_access_keys \
  --source vault \
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
  --type hashicorp_vault \
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
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod
./warden -n PROD/SEC cred spec create aws_dynamic \
  --type aws_access_keys \
  --source vault \
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




