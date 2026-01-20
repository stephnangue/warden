# test-03-storage.tf
# Tests: EBS volumes, snapshots, encryption, volume types, instance store
# Consolidates: 05-ebs-volumes, 24-ebs-snapshot, 33-instance-store

################################################################################
# Test 25: Instance with root block device configuration
################################################################################

resource "aws_instance" "with_root_volume" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name       = "${local.name_prefix}-root-volume"
    TestNumber = "25"
  }
}

################################################################################
# Test 26: Instance with additional EBS block device
################################################################################

resource "aws_instance" "with_ebs_block" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  root_block_device {
    volume_size = 30  # Must be >= AMI snapshot size
    volume_type = "gp3"
    encrypted   = true
  }

  ebs_block_device {
    device_name           = "/dev/sdf"
    volume_size           = 8
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name       = "${local.name_prefix}-ebs-block"
    TestNumber = "26"
  }
}

################################################################################
# Test 27: Standalone EBS Volume - gp3
################################################################################

resource "aws_ebs_volume" "gp3" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  type              = "gp3"
  iops              = 3000
  throughput        = 125
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-gp3"
    TestNumber = "27"
  }
}

################################################################################
# Test 28: Standalone EBS Volume - gp2
################################################################################

resource "aws_ebs_volume" "gp2" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-gp2"
    TestNumber = "28"
  }
}

################################################################################
# Test 29: Standalone EBS Volume - io1 provisioned IOPS
################################################################################

resource "aws_ebs_volume" "io1" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  type              = "io1"
  iops              = 100
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-io1"
    TestNumber = "29"
  }
}

################################################################################
# Test 30: Standalone EBS Volume - io2 provisioned IOPS
################################################################################

resource "aws_ebs_volume" "io2" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  type              = "io2"
  iops              = 100
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-io2"
    TestNumber = "30"
  }
}

################################################################################
# Test 31: Standalone EBS Volume - st1 throughput optimized HDD
################################################################################

resource "aws_ebs_volume" "st1" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 500 # Minimum 500GB for st1
  type              = "st1"
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-st1"
    TestNumber = "31"
  }
}

################################################################################
# Test 32: Standalone EBS Volume - sc1 cold HDD
################################################################################

resource "aws_ebs_volume" "sc1" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 500 # Minimum 500GB for sc1
  type              = "sc1"
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-sc1"
    TestNumber = "32"
  }
}

################################################################################
# Test 33: EBS Volume attachment
################################################################################

resource "aws_instance" "for_volume_attachment" {
  ami               = data.aws_ami.amazon_linux_2023.id
  instance_type     = "t2.micro"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name       = "${local.name_prefix}-for-vol-attach"
    TestNumber = "33"
  }
}

resource "aws_ebs_volume" "to_attach" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 8
  type              = "gp3"
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-to-attach"
    TestNumber = "33"
  }
}

resource "aws_volume_attachment" "attach" {
  device_name = "/dev/sdg"
  volume_id   = aws_ebs_volume.to_attach.id
  instance_id = aws_instance.for_volume_attachment.id
}

################################################################################
# Test 34: EBS Snapshot
################################################################################

resource "aws_ebs_volume" "for_snapshot" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 8
  type              = "gp3"
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-for-snapshot"
    TestNumber = "34"
  }
}

resource "aws_ebs_snapshot" "test" {
  volume_id = aws_ebs_volume.for_snapshot.id

  tags = {
    Name       = "${local.name_prefix}-snapshot"
    TestNumber = "34"
  }
}

################################################################################
# Test 35: EBS Volume from snapshot
################################################################################

resource "aws_ebs_volume" "from_snapshot" {
  availability_zone = data.aws_availability_zones.available.names[0]
  snapshot_id       = aws_ebs_snapshot.test.id
  encrypted         = true

  tags = {
    Name       = "${local.name_prefix}-vol-from-snapshot"
    TestNumber = "35"
  }
}

################################################################################
# Test 36: EBS Snapshot copy with encryption
################################################################################

# KNOWN LIMITATION: EBS Snapshot Copy uses presigned URLs internally that get
# malformed when proxied through Warden. The PresignedUrl path becomes invalid.
# This is similar to the MRAP limitation - AWS generates internal URLs that
# bypass or conflict with custom endpoint configuration.
#
# resource "aws_ebs_snapshot_copy" "encrypted_copy" {
#   source_snapshot_id = aws_ebs_snapshot.test.id
#   source_region      = "us-east-1"
#   encrypted          = true
#
#   tags = {
#     Name       = "${local.name_prefix}-snapshot-copy"
#     TestNumber = "36"
#   }
# }

################################################################################
# Test 37: Instance with multiple EBS volumes
################################################################################

resource "aws_instance" "multi_ebs" {
  ami               = data.aws_ami.amazon_linux_2023.id
  instance_type     = "t2.micro"
  availability_zone = data.aws_availability_zones.available.names[0]

  root_block_device {
    volume_size = 30  # Must be >= AMI snapshot size
    volume_type = "gp3"
    encrypted   = true
  }

  ebs_block_device {
    device_name = "/dev/sdf"
    volume_size = 10
    volume_type = "gp3"
    encrypted   = true
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    volume_size = 10
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name       = "${local.name_prefix}-multi-ebs"
    TestNumber = "37"
  }
}

################################################################################
# Test 38: Instance store volumes - requires instance type with ephemeral storage
################################################################################

# Note: t2/t3 don't have instance store. Use c5d, m5d, etc. for instance store.
# Skipping actual instance creation to avoid cost, but defining the pattern:

# resource "aws_instance" "with_instance_store" {
#   ami           = data.aws_ami.amazon_linux_2023.id
#   instance_type = "c5d.large"  # Has NVMe instance store
#
#   ephemeral_block_device {
#     device_name  = "/dev/sdb"
#     virtual_name = "ephemeral0"
#   }
#
#   tags = {
#     Name       = "${local.name_prefix}-instance-store"
#     TestNumber = "38"
#   }
# }

################################################################################
# Outputs
################################################################################

output "storage_instances" {
  value = {
    with_root_volume      = aws_instance.with_root_volume.id
    with_ebs_block        = aws_instance.with_ebs_block.id
    for_volume_attachment = aws_instance.for_volume_attachment.id
    multi_ebs             = aws_instance.multi_ebs.id
  }
  description = "Storage test instance IDs"
}

output "ebs_volumes" {
  value = {
    gp3           = aws_ebs_volume.gp3.id
    gp2           = aws_ebs_volume.gp2.id
    io1           = aws_ebs_volume.io1.id
    io2           = aws_ebs_volume.io2.id
    st1           = aws_ebs_volume.st1.id
    sc1           = aws_ebs_volume.sc1.id
    to_attach     = aws_ebs_volume.to_attach.id
    for_snapshot  = aws_ebs_volume.for_snapshot.id
    from_snapshot = aws_ebs_volume.from_snapshot.id
  }
  description = "EBS volume IDs"
}

output "ebs_snapshots" {
  value = {
    test = aws_ebs_snapshot.test.id
    # encrypted_copy commented out - presigned URL issue with Warden proxy
  }
  description = "EBS snapshot IDs"
}
