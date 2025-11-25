log_format  = "standard"
log_level   = "trace"

listener "mysql" {
    protocol           = "tcp"
    address            = ":4000"
}

listener "api" {
    protocol           = "tcp"
    address            = ":5000"
}

