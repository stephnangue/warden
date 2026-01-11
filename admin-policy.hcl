path "sys/cred/sources/*" {
  capabilities = ["read", "list", "delete", "create", "update", "sudo"]
}

path "sys/cred/specs/*" {
  capabilities = ["read", "list", "delete", "create", "update", "sudo"]
}

path "sys/auth/*" {
  capabilities = ["read", "delete", "create", "update", "sudo"]
}

path "sys/auth" {
  capabilities = ["list"]
}

