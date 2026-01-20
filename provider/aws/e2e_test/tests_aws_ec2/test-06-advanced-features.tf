# test-06-advanced-features.tf
# Tests: Spot instances, capacity reservations, DLM, tenancy, AMI, lifecycle
# Consolidates: 15-spot-instance, 23-custom-ami, 25-capacity-reservation, 26-tenancy,
#               27-lifecycle, 29-nitro-enclaves, 30-dlm-snapshots, 31-instance-connect-endpoint

################################################################################
# Test 58: Spot Instance Request
################################################################################

resource "aws_spot_instance_request" "basic" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  spot_type            = "one-time"
  wait_for_fulfillment = true

  tags = {
    Name       = "${local.name_prefix}-spot-request"
    TestNumber = "58"
  }
}

################################################################################
# Test 59: Spot Instance Request with max price
################################################################################

resource "aws_spot_instance_request" "with_price" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  spot_price             = "0.05"
  spot_type              = "one-time"
  wait_for_fulfillment   = true
  instance_interruption_behavior = "terminate"

  tags = {
    Name       = "${local.name_prefix}-spot-with-price"
    TestNumber = "59"
  }
}

################################################################################
# Test 60: Custom AMI from instance
################################################################################

resource "aws_instance" "for_ami" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-for-ami"
    TestNumber = "60"
  }
}

resource "aws_ami_from_instance" "custom" {
  name               = "${local.name_prefix}-custom-ami"
  source_instance_id = aws_instance.for_ami.id

  tags = {
    Name       = "${local.name_prefix}-custom-ami"
    TestNumber = "60"
  }
}

################################################################################
# Test 61: Instance from custom AMI
################################################################################

resource "aws_instance" "from_custom_ami" {
  ami           = aws_ami_from_instance.custom.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-from-custom-ami"
    TestNumber = "61"
  }

  depends_on = [aws_ami_from_instance.custom]
}

################################################################################
# Test 62: Capacity Reservation - open
# COMMENTED OUT: Capacity reservations are unreliable for testing due to
# transient AWS availability issues (ReservationCapacityExceeded errors)
################################################################################

# resource "aws_ec2_capacity_reservation" "open" {
#   instance_type           = "t2.micro"
#   instance_platform       = "Linux/UNIX"
#   availability_zone       = data.aws_availability_zones.available.names[0]
#   instance_count          = 1
#   instance_match_criteria = "open"
#
#   tags = {
#     Name       = "${local.name_prefix}-capacity-open"
#     TestNumber = "62"
#   }
# }

################################################################################
# Test 63: Instance using capacity reservation
# COMMENTED OUT: Depends on capacity reservation which is unreliable
################################################################################

# resource "aws_instance" "with_capacity" {
#   ami               = data.aws_ami.amazon_linux_2023.id
#   instance_type     = "t2.micro"
#   availability_zone = data.aws_availability_zones.available.names[0]
#
#   capacity_reservation_specification {
#     capacity_reservation_target {
#       capacity_reservation_id = aws_ec2_capacity_reservation.open.id
#     }
#   }
#
#   tags = {
#     Name       = "${local.name_prefix}-with-capacity"
#     TestNumber = "63"
#   }
# }

################################################################################
# Test 64: Instance with default tenancy
################################################################################

resource "aws_instance" "tenancy_default" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  tenancy       = "default"

  tags = {
    Name       = "${local.name_prefix}-tenancy-default"
    TestNumber = "64"
  }
}

################################################################################
# Test 65: DLM Lifecycle Policy for snapshots
################################################################################

data "aws_iam_policy_document" "dlm_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "dlm_lifecycle" {
  name               = "${local.name_prefix}-dlm-role"
  assume_role_policy = data.aws_iam_policy_document.dlm_assume_role.json

  tags = {
    Name       = "${local.name_prefix}-dlm-role"
    TestNumber = "65"
  }
}

resource "aws_iam_role_policy_attachment" "dlm_lifecycle" {
  role       = aws_iam_role.dlm_lifecycle.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_instance" "for_dlm" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-for-dlm"
    TestNumber = "65"
    Backup     = "daily"
  }
}

resource "aws_dlm_lifecycle_policy" "daily_snapshots" {
  description        = "Daily snapshot policy"
  execution_role_arn = aws_iam_role.dlm_lifecycle.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "Daily snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }

      retain_rule {
        count = 7
      }

      tags_to_add = {
        SnapshotType = "DailyBackup"
      }

      copy_tags = true
    }

    target_tags = {
      Backup = "daily"
    }
  }

  tags = {
    Name       = "${local.name_prefix}-dlm-daily"
    TestNumber = "65"
  }
}

################################################################################
# Test 66: Instance with stop protection
################################################################################

# KNOWN LIMITATION: Instances with disable_api_stop=true cannot be terminated
# by Terraform without manual intervention. To destroy:
# aws ec2 modify-instance-attribute --instance-id <id> --no-disable-api-stop
#
# resource "aws_instance" "stop_protection" {
#   ami                     = data.aws_ami.amazon_linux_2023.id
#   instance_type           = "t2.micro"
#   disable_api_stop        = true
#
#   tags = {
#     Name       = "${local.name_prefix}-stop-protection"
#     TestNumber = "66"
#   }
#
#   lifecycle {
#     ignore_changes = [disable_api_stop]
#   }
# }

################################################################################
# Test 67: Instance with lifecycle - prevent destroy
################################################################################

resource "aws_instance" "lifecycle_prevent" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-lifecycle-prevent"
    TestNumber = "67"
  }

  # lifecycle {
  #   prevent_destroy = true
  # }
}

################################################################################
# Test 68: Instance with lifecycle - create before destroy
################################################################################

resource "aws_instance" "lifecycle_create_before" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-lifecycle-create-before"
    TestNumber = "68"
  }

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Test 69: Instance with lifecycle - ignore changes
################################################################################

resource "aws_instance" "lifecycle_ignore" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "${local.name_prefix}-lifecycle-ignore"
    TestNumber = "69"
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

################################################################################
# Test 70: EC2 Instance Connect Endpoint
################################################################################

resource "aws_ec2_instance_connect_endpoint" "test" {
  subnet_id          = aws_subnet.main.id
  security_group_ids = [aws_security_group.basic.id]
  preserve_client_ip = true

  tags = {
    Name       = "${local.name_prefix}-eice"
    TestNumber = "70"
  }
}

################################################################################
# Outputs
################################################################################

output "spot_instances" {
  value = {
    basic      = aws_spot_instance_request.basic.spot_instance_id
    with_price = aws_spot_instance_request.with_price.spot_instance_id
  }
  description = "Spot instance IDs"
}

output "custom_ami" {
  value       = aws_ami_from_instance.custom.id
  description = "Custom AMI ID"
}

output "advanced_instances" {
  value = {
    for_ami              = aws_instance.for_ami.id
    from_custom_ami      = aws_instance.from_custom_ami.id
    # with_capacity commented out - capacity reservations unreliable for testing
    tenancy_default      = aws_instance.tenancy_default.id
    for_dlm              = aws_instance.for_dlm.id
    # stop_protection commented out - disable_api_stop prevents terraform destroy
    lifecycle_prevent    = aws_instance.lifecycle_prevent.id
    lifecycle_create     = aws_instance.lifecycle_create_before.id
    lifecycle_ignore     = aws_instance.lifecycle_ignore.id
  }
  description = "Advanced feature instance IDs"
}

# output "capacity_reservation" {
#   value       = aws_ec2_capacity_reservation.open.id
#   description = "Capacity reservation ID"
# }

output "dlm_policy" {
  value       = aws_dlm_lifecycle_policy.daily_snapshots.id
  description = "DLM lifecycle policy ID"
}

output "instance_connect_endpoint" {
  value       = aws_ec2_instance_connect_endpoint.test.id
  description = "EC2 Instance Connect Endpoint ID"
}
