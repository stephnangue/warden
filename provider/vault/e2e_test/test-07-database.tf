# test-07-database.tf
# Tests 91-105: Database Secrets Engine
# Tests: MySQL, PostgreSQL, MSSQL configurations and roles

################################################################################
# Database Secrets Engine Mount
################################################################################
resource "vault_mount" "database" {
  path        = "${local.name_prefix}-database"
  type        = "database"
  description = "Database secrets engine for Warden testing"

  default_lease_ttl_seconds = 300   # 5 minutes
  max_lease_ttl_seconds     = 86400 # 24 hours
}

################################################################################
# Test 91: MySQL Database Connection
################################################################################
resource "vault_database_secret_backend_connection" "mysql" {
  backend       = vault_mount.database.path
  name          = "mysql-prod"
  allowed_roles = ["mysql-readonly", "mysql-readwrite", "mysql-admin"]

  mysql {
    connection_url = "{{username}}:{{password}}@tcp(mysql.example.com:3306)/"
    username       = "vault_admin"
    password       = "vault_admin_password"
    max_open_connections = 5
    max_idle_connections = 2
    max_connection_lifetime = 300
    tls_ca         = ""
    tls_certificate_key = ""
  }

  verify_connection = false # Set false for testing without real DB
}

################################################################################
# Test 92: MySQL Read-only Role
################################################################################
resource "vault_database_secret_backend_role" "mysql_readonly" {
  backend = vault_mount.database.path
  name    = "mysql-readonly"
  db_name = vault_database_secret_backend_connection.mysql.name

  creation_statements = [
    "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
    "GRANT SELECT ON *.* TO '{{name}}'@'%';",
  ]

  revocation_statements = [
    "DROP USER IF EXISTS '{{name}}'@'%';",
  ]

  default_ttl = 300   # 5 minutes
  max_ttl     = 3600  # 1 hour
}

################################################################################
# Test 93: MySQL Read-Write Role
################################################################################
resource "vault_database_secret_backend_role" "mysql_readwrite" {
  backend = vault_mount.database.path
  name    = "mysql-readwrite"
  db_name = vault_database_secret_backend_connection.mysql.name

  creation_statements = [
    "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO '{{name}}'@'%';",
  ]

  revocation_statements = [
    "DROP USER IF EXISTS '{{name}}'@'%';",
  ]

  default_ttl = 600   # 10 minutes
  max_ttl     = 7200  # 2 hours
}

################################################################################
# Test 94: MySQL Admin Role
################################################################################
resource "vault_database_secret_backend_role" "mysql_admin" {
  backend = vault_mount.database.path
  name    = "mysql-admin"
  db_name = vault_database_secret_backend_connection.mysql.name

  creation_statements = [
    "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
    "GRANT ALL PRIVILEGES ON *.* TO '{{name}}'@'%' WITH GRANT OPTION;",
  ]

  revocation_statements = [
    "DROP USER IF EXISTS '{{name}}'@'%';",
  ]

  default_ttl = 1800  # 30 minutes
  max_ttl     = 14400 # 4 hours
}

################################################################################
# Test 95: PostgreSQL Database Connection
################################################################################
resource "vault_database_secret_backend_connection" "postgresql" {
  backend       = vault_mount.database.path
  name          = "postgresql-prod"
  allowed_roles = ["postgresql-readonly", "postgresql-readwrite", "postgresql-admin"]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@postgres.example.com:5432/mydb?sslmode=require"
    username       = "vault_admin"
    password       = "vault_admin_password"
    max_open_connections = 5
    max_idle_connections = 2
    max_connection_lifetime = 300
  }

  verify_connection = false
}

################################################################################
# Test 96: PostgreSQL Read-only Role
################################################################################
resource "vault_database_secret_backend_role" "postgresql_readonly" {
  backend = vault_mount.database.path
  name    = "postgresql-readonly"
  db_name = vault_database_secret_backend_connection.postgresql.name

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";",
  ]

  revocation_statements = [
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
    "DROP OWNED BY \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  renew_statements = [
    "ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}';",
  ]

  default_ttl = 300
  max_ttl     = 3600
}

################################################################################
# Test 97: PostgreSQL Read-Write Role
################################################################################
resource "vault_database_secret_backend_role" "postgresql_readwrite" {
  backend = vault_mount.database.path
  name    = "postgresql-readwrite"
  db_name = vault_database_secret_backend_connection.postgresql.name

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";",
  ]

  revocation_statements = [
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
    "DROP OWNED BY \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  default_ttl = 600
  max_ttl     = 7200
}

################################################################################
# Test 98: PostgreSQL Admin Role
################################################################################
resource "vault_database_secret_backend_role" "postgresql_admin" {
  backend = vault_mount.database.path
  name    = "postgresql-admin"
  db_name = vault_database_secret_backend_connection.postgresql.name

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH SUPERUSER LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
  ]

  revocation_statements = [
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
    "DROP OWNED BY \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  default_ttl = 1800
  max_ttl     = 14400
}

################################################################################
# Test 99: MSSQL Database Connection
################################################################################
resource "vault_database_secret_backend_connection" "mssql" {
  backend       = vault_mount.database.path
  name          = "mssql-prod"
  allowed_roles = ["mssql-readonly", "mssql-readwrite"]

  mssql {
    connection_url = "sqlserver://{{username}}:{{password}}@mssql.example.com:1433"
    username       = "vault_admin"
    password       = "vault_admin_password"
    max_open_connections = 5
    max_idle_connections = 2
    max_connection_lifetime = 300
  }

  verify_connection = false
}

################################################################################
# Test 100: MSSQL Read-only Role
################################################################################
resource "vault_database_secret_backend_role" "mssql_readonly" {
  backend = vault_mount.database.path
  name    = "mssql-readonly"
  db_name = vault_database_secret_backend_connection.mssql.name

  creation_statements = [
    "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
    "CREATE USER [{{name}}] FOR LOGIN [{{name}}];",
    "GRANT SELECT TO [{{name}}];",
  ]

  revocation_statements = [
    "IF EXISTS (SELECT name FROM sys.database_principals WHERE name = '{{name}}') DROP USER [{{name}}];",
    "IF EXISTS (SELECT name FROM sys.server_principals WHERE name = '{{name}}') DROP LOGIN [{{name}}];",
  ]

  default_ttl = 300
  max_ttl     = 3600
}

################################################################################
# Test 101: MSSQL Read-Write Role
################################################################################
resource "vault_database_secret_backend_role" "mssql_readwrite" {
  backend = vault_mount.database.path
  name    = "mssql-readwrite"
  db_name = vault_database_secret_backend_connection.mssql.name

  creation_statements = [
    "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
    "CREATE USER [{{name}}] FOR LOGIN [{{name}}];",
    "GRANT SELECT, INSERT, UPDATE, DELETE TO [{{name}}];",
  ]

  revocation_statements = [
    "IF EXISTS (SELECT name FROM sys.database_principals WHERE name = '{{name}}') DROP USER [{{name}}];",
    "IF EXISTS (SELECT name FROM sys.server_principals WHERE name = '{{name}}') DROP LOGIN [{{name}}];",
  ]

  default_ttl = 600
  max_ttl     = 7200
}

################################################################################
# Test 102: MongoDB Database Connection
################################################################################
resource "vault_database_secret_backend_connection" "mongodb" {
  backend       = vault_mount.database.path
  name          = "mongodb-prod"
  allowed_roles = ["mongodb-readonly", "mongodb-readwrite"]

  mongodb {
    connection_url = "mongodb://{{username}}:{{password}}@mongo.example.com:27017/admin?ssl=true"
    username       = "vault_admin"
    password       = "vault_admin_password"
  }

  verify_connection = false
}

################################################################################
# Test 103: MongoDB Read-only Role
################################################################################
resource "vault_database_secret_backend_role" "mongodb_readonly" {
  backend = vault_mount.database.path
  name    = "mongodb-readonly"
  db_name = vault_database_secret_backend_connection.mongodb.name

  creation_statements = [
    "{\"db\": \"admin\", \"roles\": [{\"role\": \"read\", \"db\": \"mydb\"}]}",
  ]

  default_ttl = 300
  max_ttl     = 3600
}

################################################################################
# Test 104: MongoDB Read-Write Role
################################################################################
resource "vault_database_secret_backend_role" "mongodb_readwrite" {
  backend = vault_mount.database.path
  name    = "mongodb-readwrite"
  db_name = vault_database_secret_backend_connection.mongodb.name

  creation_statements = [
    "{\"db\": \"admin\", \"roles\": [{\"role\": \"readWrite\", \"db\": \"mydb\"}]}",
  ]

  default_ttl = 600
  max_ttl     = 7200
}

################################################################################
# Test 105: Redis Connection
################################################################################
resource "vault_database_secret_backend_connection" "redis" {
  backend       = vault_mount.database.path
  name          = "redis-prod"
  allowed_roles = ["redis-user"]

  redis {
    host     = "redis.example.com"
    port     = 6379
    username = "vault-admin"
    password = "test-password"
    tls      = false
  }

  verify_connection = false
}

################################################################################
# Outputs
################################################################################

output "database_mount_path" {
  value       = vault_mount.database.path
  description = "Database secrets engine mount path"
}

output "database_connections" {
  value = {
    mysql      = vault_database_secret_backend_connection.mysql.name
    postgresql = vault_database_secret_backend_connection.postgresql.name
    mssql      = vault_database_secret_backend_connection.mssql.name
    mongodb    = vault_database_secret_backend_connection.mongodb.name
  }
  description = "Database connection names"
}

output "database_roles" {
  value = {
    mysql = {
      readonly  = vault_database_secret_backend_role.mysql_readonly.name
      readwrite = vault_database_secret_backend_role.mysql_readwrite.name
      admin     = vault_database_secret_backend_role.mysql_admin.name
    }
    postgresql = {
      readonly  = vault_database_secret_backend_role.postgresql_readonly.name
      readwrite = vault_database_secret_backend_role.postgresql_readwrite.name
      admin     = vault_database_secret_backend_role.postgresql_admin.name
    }
    mssql = {
      readonly  = vault_database_secret_backend_role.mssql_readonly.name
      readwrite = vault_database_secret_backend_role.mssql_readwrite.name
    }
    mongodb = {
      readonly  = vault_database_secret_backend_role.mongodb_readonly.name
      readwrite = vault_database_secret_backend_role.mongodb_readwrite.name
    }
  }
  description = "Database role names for dynamic credentials"
}

output "database_role_ttls" {
  value = {
    mysql_readonly = {
      default_ttl = vault_database_secret_backend_role.mysql_readonly.default_ttl
      max_ttl     = vault_database_secret_backend_role.mysql_readonly.max_ttl
    }
    postgresql_readonly = {
      default_ttl = vault_database_secret_backend_role.postgresql_readonly.default_ttl
      max_ttl     = vault_database_secret_backend_role.postgresql_readonly.max_ttl
    }
  }
  description = "Database role TTL configurations"
}
