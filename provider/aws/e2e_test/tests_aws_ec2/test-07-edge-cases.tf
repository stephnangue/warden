# test-07-edge-cases.tf
# Tests: Edge cases that could break Warden proxying for EC2 API
# Categories: Tags, Security Groups, UserData, Instance Names, Network, EBS

################################################################################
# Test 71: Tag with Unicode characters
################################################################################

resource "aws_instance" "tag_unicode" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name          = "${local.name_prefix}-tag-unicode"
    TestNumber    = "71"
    UnicodeKey    = "Value with unicode: cafe"
    ChineseChars  = "Chinese chars test"
    JapaneseChars = "Japanese chars test"
    EmojiTest     = "Emoji test"
    Accents       = "Accented: cafe resume naive"
  }
}

################################################################################
# Test 72: Tag with maximum key length (128 chars)
################################################################################

resource "aws_instance" "tag_max_key_length" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name       = "${local.name_prefix}-tag-max-key"
    TestNumber = "72"
    # AWS allows up to 128 characters for tag keys
    "ThisIsAVeryLongTagKeyThatIsDesignedToTestTheMaximumAllowedLengthForAWSResourceTagKeysWhichIs128Characters12345678" = "max-key-test"
  }
}

################################################################################
# Test 73: Tag with maximum value length (256 chars)
################################################################################

resource "aws_instance" "tag_max_value_length" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name       = "${local.name_prefix}-tag-max-value"
    TestNumber = "73"
    # AWS allows up to 256 characters for tag values
    LongValue = "ThisIsAVeryLongTagValueThatIsDesignedToTestTheMaximumAllowedLengthForAWSResourceTagValuesWhichIs256CharactersAndWeNeedToMakeThisStringLongEnoughToReachThatLimitSoWeKeepAddingMoreTextUntilWeGetThere12345678901234567890123456789012345678901234567890"
  }
}

################################################################################
# Test 74: Tag with special characters
################################################################################

resource "aws_instance" "tag_special_chars" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name                = "${local.name_prefix}-tag-special"
    TestNumber          = "74"
    "Key-With-Dashes"   = "dashes-in-value"
    "Key_With_Underscores" = "underscores_in_value"
    "Key.With.Dots"     = "dots.in.value"
    "Key:With:Colons"   = "colons:in:value"
    "Key/With/Slashes"  = "slashes/in/value"
    "Key+With+Plus"     = "plus+in+value"
    "Key=With=Equals"   = "equals=in=value"
    "Key@With@At"       = "at@in@value"
  }
}

################################################################################
# Test 75: Tag with empty value
################################################################################

resource "aws_instance" "tag_empty_value" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name       = "${local.name_prefix}-tag-empty"
    TestNumber = "75"
    EmptyValue = ""
  }
}

################################################################################
# Test 76: Maximum number of tags (50 tags)
################################################################################

resource "aws_instance" "tag_max_count" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = merge(
    {
      Name       = "${local.name_prefix}-tag-max-count"
      TestNumber = "76"
    },
    { for i in range(1, 49) : "Tag${format("%02d", i)}" => "Value${i}" }
  )
}

################################################################################
# Test 77: Security Group with IPv6 CIDR
################################################################################

resource "aws_security_group" "ipv6" {
  name        = "${local.name_prefix}-sg-ipv6"
  description = "Security group with IPv6 rules"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-ipv6"
    TestNumber = "77"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ipv6_ssh" {
  security_group_id = aws_security_group.ipv6.id
  description       = "SSH from IPv6"
  cidr_ipv6         = "::/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ipv6_http" {
  security_group_id = aws_security_group.ipv6.id
  description       = "HTTP from IPv6"
  cidr_ipv6         = "::/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ipv6_all" {
  security_group_id = aws_security_group.ipv6.id
  description       = "All outbound IPv6"
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 78: Security Group with ICMP protocol
################################################################################

resource "aws_security_group" "icmp" {
  name        = "${local.name_prefix}-sg-icmp"
  description = "Security group with ICMP rules"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-icmp"
    TestNumber = "78"
  }
}

resource "aws_vpc_security_group_ingress_rule" "icmp_ping" {
  security_group_id = aws_security_group.icmp.id
  description       = "Allow ping (ICMP echo)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8  # ICMP type: echo request
  to_port           = 0  # ICMP code
  ip_protocol       = "icmp"
}

resource "aws_vpc_security_group_ingress_rule" "icmp_all" {
  security_group_id = aws_security_group.icmp.id
  description       = "Allow all ICMP"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = -1  # All ICMP types
  to_port           = -1  # All ICMP codes
  ip_protocol       = "icmp"
}

resource "aws_vpc_security_group_egress_rule" "icmp_outbound" {
  security_group_id = aws_security_group.icmp.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 79: Security Group with port range
################################################################################

resource "aws_security_group" "port_range" {
  name        = "${local.name_prefix}-sg-port-range"
  description = "Security group with port ranges"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-port-range"
    TestNumber = "79"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ephemeral_ports" {
  security_group_id = aws_security_group.port_range.id
  description       = "Ephemeral ports range"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 1024
  to_port           = 65535
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "custom_range" {
  security_group_id = aws_security_group.port_range.id
  description       = "Custom port range"
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 8000
  to_port           = 9000
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "port_range_outbound" {
  security_group_id = aws_security_group.port_range.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 80: Security Group with UDP protocol
################################################################################

resource "aws_security_group" "udp" {
  name        = "${local.name_prefix}-sg-udp"
  description = "Security group with UDP rules"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-udp"
    TestNumber = "80"
  }
}

resource "aws_vpc_security_group_ingress_rule" "udp_dns" {
  security_group_id = aws_security_group.udp.id
  description       = "DNS over UDP"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "udp_ntp" {
  security_group_id = aws_security_group.udp.id
  description       = "NTP over UDP"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 123
  to_port           = 123
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "udp_outbound" {
  security_group_id = aws_security_group.udp.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 81: Security Group with specific CIDR blocks
################################################################################

resource "aws_security_group" "specific_cidr" {
  name        = "${local.name_prefix}-sg-specific-cidr"
  description = "Security group with specific CIDR blocks"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-specific-cidr"
    TestNumber = "81"
  }
}

resource "aws_vpc_security_group_ingress_rule" "cidr_class_a" {
  security_group_id = aws_security_group.specific_cidr.id
  description       = "Class A private range"
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "cidr_class_b" {
  security_group_id = aws_security_group.specific_cidr.id
  description       = "Class B private range"
  cidr_ipv4         = "172.16.0.0/12"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "cidr_class_c" {
  security_group_id = aws_security_group.specific_cidr.id
  description       = "Class C private range"
  cidr_ipv4         = "192.168.0.0/16"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "cidr_single_host" {
  security_group_id = aws_security_group.specific_cidr.id
  description       = "Single host (/32)"
  cidr_ipv4         = "203.0.113.50/32"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "specific_cidr_outbound" {
  security_group_id = aws_security_group.specific_cidr.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Test 82: UserData with special characters
################################################################################

resource "aws_instance" "userdata_special" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Test script with special characters
    echo "Hello World!"
    echo "Special chars: \$VAR @user #comment &background"
    echo "Quotes: 'single' and \"double\""
    echo "Path: /path/to/file"
    echo "Math: 1+1=2"
    export MY_VAR="value with spaces"
    echo $MY_VAR
    EOF
  )

  tags = {
    Name       = "${local.name_prefix}-userdata-special"
    TestNumber = "82"
  }
}

################################################################################
# Test 83: UserData with cloud-init YAML
################################################################################

resource "aws_instance" "userdata_cloudinit" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  user_data = base64encode(<<-EOF
    #cloud-config
    packages:
      - httpd
      - vim
    write_files:
      - path: /etc/test/config.txt
        content: |
          key1=value1
          key2=value2
        permissions: '0644'
    runcmd:
      - echo "Cloud-init complete" >> /var/log/cloud-init-test.log
    EOF
  )

  tags = {
    Name       = "${local.name_prefix}-userdata-cloudinit"
    TestNumber = "83"
  }
}

################################################################################
# Test 84: UserData with multiline script
################################################################################

resource "aws_instance" "userdata_multiline" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # Function definition
    log_message() {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/startup.log
    }

    # Multi-line heredoc inside userdata
    cat > /tmp/config.json << 'JSONEOF'
    {
        "setting1": "value1",
        "setting2": true,
        "setting3": 123
    }
    JSONEOF

    log_message "Configuration written"

    # Loop
    for i in {1..5}; do
        log_message "Iteration $i"
    done

    log_message "Startup complete"
    EOF
  )

  tags = {
    Name       = "${local.name_prefix}-userdata-multiline"
    TestNumber = "84"
  }
}

################################################################################
# Test 85: Instance name with path-like characters
################################################################################

resource "aws_instance" "name_path_like" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name       = "${local.name_prefix}/app/web/server-01"
    TestNumber = "85"
  }
}

################################################################################
# Test 86: Instance with description containing special chars
################################################################################

resource "aws_instance" "description_special" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name        = "${local.name_prefix}-desc-special"
    TestNumber  = "86"
    Description = "Server for app-v2.0 (production) - team: platform@company.com [priority=high]"
  }
}

################################################################################
# Test 87: Network interface with source/dest check disabled
################################################################################

resource "aws_network_interface" "no_source_dest" {
  subnet_id         = aws_subnet.main.id
  security_groups   = [aws_security_group.basic.id]
  source_dest_check = false

  tags = {
    Name       = "${local.name_prefix}-eni-no-source-dest"
    TestNumber = "87"
  }
}

resource "aws_instance" "nat_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  network_interface {
    network_interface_id = aws_network_interface.no_source_dest.id
    device_index         = 0
  }

  tags = {
    Name       = "${local.name_prefix}-nat-instance"
    TestNumber = "87"
  }
}

################################################################################
# Test 88: Instance with multiple network interfaces
################################################################################

resource "aws_network_interface" "secondary_eni" {
  subnet_id       = aws_subnet.main.id
  security_groups = [aws_security_group.basic.id]
  private_ips     = ["10.0.1.200"]

  tags = {
    Name       = "${local.name_prefix}-eni-secondary"
    TestNumber = "88"
  }
}

resource "aws_instance" "multi_eni" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  tags = {
    Name       = "${local.name_prefix}-multi-eni"
    TestNumber = "88"
  }
}

resource "aws_network_interface_attachment" "secondary" {
  instance_id          = aws_instance.multi_eni.id
  network_interface_id = aws_network_interface.secondary_eni.id
  device_index         = 1
}

################################################################################
# Test 89: EBS volume with maximum IOPS (gp3)
################################################################################

resource "aws_instance" "ebs_max_iops" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  root_block_device {
    volume_type = "gp3"
    volume_size = 100
    iops        = 16000  # Max for gp3
    throughput  = 1000   # Max throughput for gp3
  }

  tags = {
    Name       = "${local.name_prefix}-ebs-max-iops"
    TestNumber = "89"
  }
}

################################################################################
# Test 90: EBS volume with io2 and high IOPS
################################################################################

resource "aws_ebs_volume" "io2_high_iops" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 100
  type              = "io2"
  iops              = 5000  # io2 allows up to 64000 IOPS but requires larger volume

  tags = {
    Name       = "${local.name_prefix}-vol-io2-high-iops"
    TestNumber = "90"
  }
}

################################################################################
# Test 91: EBS volume with encryption and custom KMS key
################################################################################

resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS encryption test"
  deletion_window_in_days = 7

  tags = {
    Name       = "${local.name_prefix}-kms-ebs"
    TestNumber = "91"
  }
}

resource "aws_ebs_volume" "encrypted_custom_kms" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn

  tags = {
    Name       = "${local.name_prefix}-vol-encrypted-kms"
    TestNumber = "91"
  }
}

################################################################################
# Test 92: Instance with multiple EBS volumes
################################################################################

resource "aws_instance" "multi_volume" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id

  root_block_device {
    volume_type = "gp3"
    volume_size = 30  # Must be >= AMI snapshot size (30GB)
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    volume_type = "gp3"
    volume_size = 50
  }

  ebs_block_device {
    device_name = "/dev/sdc"
    volume_type = "gp2"
    volume_size = 30
  }

  ebs_block_device {
    device_name = "/dev/sdd"
    volume_type = "st1"
    volume_size = 500  # st1 minimum
  }

  tags = {
    Name       = "${local.name_prefix}-multi-volume"
    TestNumber = "92"
  }
}

################################################################################
# Test 93: Instance with ephemeral storage
################################################################################

resource "aws_instance" "ephemeral_storage" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "m5d.large"  # Instance type with instance store
  subnet_id     = aws_subnet.main.id

  ephemeral_block_device {
    device_name  = "/dev/sdb"
    virtual_name = "ephemeral0"
  }

  tags = {
    Name       = "${local.name_prefix}-ephemeral-storage"
    TestNumber = "93"
  }
}

################################################################################
# Test 94: Placement group - cluster
################################################################################

resource "aws_placement_group" "cluster" {
  name     = "${local.name_prefix}-pg-cluster"
  strategy = "cluster"

  tags = {
    Name       = "${local.name_prefix}-pg-cluster"
    TestNumber = "94"
  }
}

################################################################################
# Test 95: Placement group - spread
################################################################################

resource "aws_placement_group" "spread" {
  name     = "${local.name_prefix}-pg-spread"
  strategy = "spread"

  tags = {
    Name       = "${local.name_prefix}-pg-spread"
    TestNumber = "95"
  }
}

################################################################################
# Test 96: Placement group - partition
################################################################################

resource "aws_placement_group" "partition" {
  name            = "${local.name_prefix}-pg-partition"
  strategy        = "partition"
  partition_count = 3

  tags = {
    Name       = "${local.name_prefix}-pg-partition"
    TestNumber = "96"
  }
}

################################################################################
# Test 97: Instance in placement group
################################################################################

resource "aws_instance" "in_placement_group" {
  ami             = data.aws_ami.amazon_linux_2023.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main.id
  placement_group = aws_placement_group.spread.id

  tags = {
    Name       = "${local.name_prefix}-in-pg"
    TestNumber = "97"
  }
}

################################################################################
# Test 98: Instance with hibernation enabled
################################################################################

resource "aws_instance" "hibernation" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.main.id
  hibernation   = true

  root_block_device {
    volume_type = "gp3"
    volume_size = 30  # Must be >= AMI snapshot size (30GB)
    encrypted   = true  # Required for hibernation
  }

  tags = {
    Name       = "${local.name_prefix}-hibernation"
    TestNumber = "98"
  }
}

################################################################################
# Test 99: Instance with host resource group
################################################################################

# Note: Dedicated hosts require specific configuration and may incur costs
# This test creates the placement configuration but may need actual dedicated host

resource "aws_instance" "host_tenancy" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.main.id
  tenancy       = "default"  # Change to "host" for actual dedicated host testing

  tags = {
    Name       = "${local.name_prefix}-host-tenancy"
    TestNumber = "99"
  }
}

################################################################################
# Test 100: Security Group with self-reference
################################################################################

resource "aws_security_group" "self_reference" {
  name        = "${local.name_prefix}-sg-self-ref"
  description = "Security group with self-referencing rule"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-self-ref"
    TestNumber = "100"
  }
}

resource "aws_vpc_security_group_ingress_rule" "self_ref" {
  security_group_id            = aws_security_group.self_reference.id
  description                  = "Allow traffic from same security group"
  referenced_security_group_id = aws_security_group.self_reference.id
  from_port                    = 0
  to_port                      = 65535
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "self_ref_outbound" {
  security_group_id = aws_security_group.self_reference.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Outputs
################################################################################

output "edge_case_tag_instances" {
  value = {
    unicode          = aws_instance.tag_unicode.id
    max_key_length   = aws_instance.tag_max_key_length.id
    max_value_length = aws_instance.tag_max_value_length.id
    special_chars    = aws_instance.tag_special_chars.id
    empty_value      = aws_instance.tag_empty_value.id
    max_count        = aws_instance.tag_max_count.id
  }
  description = "Tag edge case instance IDs"
}

output "edge_case_security_groups" {
  value = {
    ipv6          = aws_security_group.ipv6.id
    icmp          = aws_security_group.icmp.id
    port_range    = aws_security_group.port_range.id
    udp           = aws_security_group.udp.id
    specific_cidr = aws_security_group.specific_cidr.id
    self_ref      = aws_security_group.self_reference.id
  }
  description = "Security group edge case IDs"
}

output "edge_case_userdata_instances" {
  value = {
    special    = aws_instance.userdata_special.id
    cloudinit  = aws_instance.userdata_cloudinit.id
    multiline  = aws_instance.userdata_multiline.id
  }
  description = "UserData edge case instance IDs"
}

output "edge_case_name_instances" {
  value = {
    path_like   = aws_instance.name_path_like.id
    desc_special = aws_instance.description_special.id
  }
  description = "Name/description edge case instance IDs"
}

output "edge_case_network_instances" {
  value = {
    nat_instance = aws_instance.nat_instance.id
    multi_eni    = aws_instance.multi_eni.id
  }
  description = "Network edge case instance IDs"
}

output "edge_case_ebs" {
  value = {
    max_iops_instance = aws_instance.ebs_max_iops.id
    io2_volume        = aws_ebs_volume.io2_high_iops.id
    encrypted_kms     = aws_ebs_volume.encrypted_custom_kms.id
    multi_volume      = aws_instance.multi_volume.id
    ephemeral         = aws_instance.ephemeral_storage.id
  }
  description = "EBS edge case resource IDs"
}

output "edge_case_placement_groups" {
  value = {
    cluster   = aws_placement_group.cluster.id
    spread    = aws_placement_group.spread.id
    partition = aws_placement_group.partition.id
  }
  description = "Placement group IDs"
}

output "edge_case_advanced" {
  value = {
    in_pg       = aws_instance.in_placement_group.id
    hibernation = aws_instance.hibernation.id
    host_tenancy = aws_instance.host_tenancy.id
  }
  description = "Advanced feature edge case instance IDs"
}
