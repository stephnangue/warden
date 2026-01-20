# test-02-networking.tf
# Tests: Security groups, network interfaces, elastic IPs
# Note: VPC, subnets, and basic security group are defined in main.tf
# Consolidates: 02-security-group, 07-elastic-ip, 09-network-interface, 28-multiple-security-groups

################################################################################
# Test 13: Security Group for web servers
################################################################################

resource "aws_security_group" "web" {
  name        = "${local.name_prefix}-sg-web"
  description = "Web server security group"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-web"
    TestNumber = "14"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web.id
  description       = "HTTP access"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS access"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "web_outbound" {
  security_group_id = aws_security_group.web.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 15: Security Group for database
################################################################################

resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-sg-db"
  description = "Database security group"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-db"
    TestNumber = "15"
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_mysql" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from web servers"
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "db_outbound" {
  security_group_id = aws_security_group.db.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 16: Instance with security group
################################################################################

resource "aws_instance" "with_sg" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-with-sg"
    TestNumber = "16"
  }
}

################################################################################
# Test 17: Instance with multiple security groups
################################################################################

resource "aws_instance" "with_multiple_sgs" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id, aws_security_group.web.id]

  tags = {
    Name       = "${local.name_prefix}-multiple-sgs"
    TestNumber = "17"
  }
}

################################################################################
# Test 18: Instance in custom VPC
################################################################################

resource "aws_instance" "in_vpc" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-in-vpc"
    TestNumber = "18"
  }
}

################################################################################
# Test 19: Network Interface - standalone
################################################################################

resource "aws_network_interface" "standalone" {
  subnet_id       = aws_subnet.main.id
  security_groups = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-eni-standalone"
    TestNumber = "19"
  }
}

################################################################################
# Test 20: Network Interface with multiple private IPs
################################################################################

resource "aws_network_interface" "multi_ip" {
  subnet_id       = aws_subnet.main.id
  private_ips     = ["10.0.1.100", "10.0.1.101", "10.0.1.102"]
  security_groups = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-eni-multi-ip"
    TestNumber = "20"
  }
}

################################################################################
# Test 21: Instance with attached network interface
################################################################################

resource "aws_network_interface" "for_instance" {
  subnet_id       = aws_subnet.main.id
  security_groups = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-eni-for-instance"
    TestNumber = "21"
  }
}

resource "aws_instance" "with_eni" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  network_interface {
    network_interface_id = aws_network_interface.for_instance.id
    device_index         = 0
  }

  tags = {
    Name       = "${local.name_prefix}-with-eni"
    TestNumber = "21"
  }
}

################################################################################
# Test 22: Elastic IP
################################################################################

resource "aws_eip" "standalone" {
  domain = "vpc"

  tags = {
    Name       = "${local.name_prefix}-eip-standalone"
    TestNumber = "22"
  }
}

################################################################################
# Test 23: Elastic IP associated with instance
################################################################################

resource "aws_instance" "for_eip" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-for-eip"
    TestNumber = "23"
  }
}

resource "aws_eip" "for_instance" {
  instance = aws_instance.for_eip.id
  domain   = "vpc"

  tags = {
    Name       = "${local.name_prefix}-eip-for-instance"
    TestNumber = "23"
  }
}

################################################################################
# Test 24: Elastic IP associated with network interface
################################################################################

resource "aws_network_interface" "for_eip" {
  subnet_id       = aws_subnet.main.id
  security_groups = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-eni-for-eip"
    TestNumber = "24"
  }
}

resource "aws_eip" "for_eni" {
  domain = "vpc"

  tags = {
    Name       = "${local.name_prefix}-eip-for-eni"
    TestNumber = "24"
  }
}

resource "aws_eip_association" "eni" {
  network_interface_id = aws_network_interface.for_eip.id
  allocation_id        = aws_eip.for_eni.id
}

################################################################################
# Outputs
################################################################################

output "security_group_ids" {
  value = {
    web = aws_security_group.web.id
    db  = aws_security_group.db.id
  }
  description = "Security group IDs (additional to basic in main.tf)"
}

output "network_instances" {
  value = {
    with_sg           = aws_instance.with_sg.id
    with_multiple_sgs = aws_instance.with_multiple_sgs.id
    in_vpc            = aws_instance.in_vpc.id
    with_eni          = aws_instance.with_eni.id
    for_eip           = aws_instance.for_eip.id
  }
  description = "Network test instance IDs"
}

output "elastic_ips" {
  value = {
    standalone   = aws_eip.standalone.public_ip
    for_instance = aws_eip.for_instance.public_ip
    for_eni      = aws_eip.for_eni.public_ip
  }
  description = "Elastic IP addresses"
}
