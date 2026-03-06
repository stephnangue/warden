log_format  = "standard"
log_level   = "trace"

min_cred_source_rotation_period = "5m"
min_cred_spec_rotation_period   = "5m"

ip_binding_policy = "disabled"

api_addr     = "http://127.0.0.1:8520"
cluster_addr = "https://127.0.0.1:8521"

seal "static" {
  current_key_id = "20251221-1"
  current_key = "file://./seal.key"
}

storage "postgres" {
  connection_url = "postgres://warden:wardenpassword@localhost:5433/warden?sslmode=disable"
  table          = "e2e_kv_store"
  ha_enabled     = "true"
  ha_table       = "e2e_ha_locks"
}

listener "tcp" {
    address         = "0.0.0.0:8520"
    tls_enabled     = false
    trusted_proxies = ["127.0.0.1/32", "172.16.0.0/12", "192.168.0.0/16"]
}
