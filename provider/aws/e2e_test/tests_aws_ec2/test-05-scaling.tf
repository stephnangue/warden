# test-05-scaling.tf
# Tests: Launch templates, Auto Scaling Groups, EC2 Fleet
# Consolidates: 21-launch-template, 22-auto-scaling-group, 32-ec2-fleet

################################################################################
# Test 47: Basic Launch Template
################################################################################

resource "aws_launch_template" "basic" {
  name          = "${local.name_prefix}-lt-basic"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-from-lt-basic"
      TestNumber = "47"
    }
  }

  tags = {
    Name       = "${local.name_prefix}-lt-basic"
    TestNumber = "47"
  }
}

################################################################################
# Test 48: Launch Template with all options
################################################################################

resource "aws_launch_template" "full" {
  name          = "${local.name_prefix}-lt-full"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.basic.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-from-lt-full"
      TestNumber = "48"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name       = "${local.name_prefix}-vol-from-lt"
      TestNumber = "48"
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "Launched from full template" > /tmp/launch-info.txt
  EOF
  )

  tags = {
    Name       = "${local.name_prefix}-lt-full"
    TestNumber = "48"
  }
}

################################################################################
# Test 49: Instance from Launch Template
################################################################################

resource "aws_instance" "from_launch_template" {
  launch_template {
    id      = aws_launch_template.basic.id
    version = "$Latest"
  }

  tags = {
    Name       = "${local.name_prefix}-from-lt"
    TestNumber = "49"
  }
}

################################################################################
# Test 50: Instance from Launch Template with version
################################################################################

resource "aws_instance" "from_launch_template_version" {
  launch_template {
    id      = aws_launch_template.basic.id
    version = aws_launch_template.basic.latest_version
  }

  tags = {
    Name       = "${local.name_prefix}-from-lt-version"
    TestNumber = "50"
  }
}

################################################################################
# Test 51: Launch Template for ASG
################################################################################

resource "aws_launch_template" "for_asg" {
  name_prefix   = "${local.name_prefix}-lt-asg-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-asg-instance"
      TestNumber = "51"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Test 52: Basic Auto Scaling Group
################################################################################

resource "aws_autoscaling_group" "basic" {
  name                = "${local.name_prefix}-asg-basic"
  desired_capacity    = 1
  max_size            = 2
  min_size            = 1
  vpc_zone_identifier = [aws_subnet.main.id, aws_subnet.secondary.id]

  launch_template {
    id      = aws_launch_template.for_asg.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-asg-basic"
    propagate_at_launch = true
  }

  tag {
    key                 = "TestNumber"
    value               = "52"
    propagate_at_launch = true
  }
}

################################################################################
# Test 53: Auto Scaling Group with scaling policies
################################################################################

resource "aws_launch_template" "for_asg_scaling" {
  name_prefix   = "${local.name_prefix}-lt-asg-scaling-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-asg-scaling-instance"
      TestNumber = "53"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "with_scaling" {
  name                = "${local.name_prefix}-asg-scaling"
  desired_capacity    = 1
  max_size            = 3
  min_size            = 1
  vpc_zone_identifier = [aws_subnet.main.id]
  health_check_type   = "EC2"

  launch_template {
    id      = aws_launch_template.for_asg_scaling.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-asg-scaling"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "scale_up" {
  name                   = "${local.name_prefix}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.with_scaling.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "${local.name_prefix}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.with_scaling.name
}

################################################################################
# Test 54: Auto Scaling Group with target tracking
################################################################################

resource "aws_launch_template" "for_asg_target" {
  name_prefix   = "${local.name_prefix}-lt-asg-target-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-asg-target-instance"
      TestNumber = "54"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "with_target_tracking" {
  name                = "${local.name_prefix}-asg-target"
  desired_capacity    = 1
  max_size            = 3
  min_size            = 1
  vpc_zone_identifier = [aws_subnet.main.id]

  launch_template {
    id      = aws_launch_template.for_asg_target.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-asg-target"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "target_tracking" {
  name                   = "${local.name_prefix}-target-tracking"
  policy_type            = "TargetTrackingScaling"
  autoscaling_group_name = aws_autoscaling_group.with_target_tracking.name

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

################################################################################
# Test 55: Launch Template for Fleet
################################################################################

resource "aws_launch_template" "for_fleet" {
  name          = "${local.name_prefix}-lt-fleet"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-fleet-instance"
      TestNumber = "55"
    }
  }
}

################################################################################
# Test 56: EC2 Fleet - instant type
################################################################################

# KNOWN LIMITATION: Instant fleets cannot be managed by Terraform because:
# 1. AWS doesn't support the terminate_instances option for instant fleets
# 2. Terraform always tries to set this option during deletion
# See: https://github.com/hashicorp/terraform-provider-aws/issues/
#
# resource "aws_ec2_fleet" "instant" {
#   type = "instant"
#
#   launch_template_config {
#     launch_template_specification {
#       launch_template_id = aws_launch_template.for_fleet.id
#       version            = "$Latest"
#     }
#
#     override {
#       instance_type = "t2.micro"
#     }
#
#     override {
#       instance_type = "t3.micro"
#     }
#   }
#
#   target_capacity_specification {
#     default_target_capacity_type = "on-demand"
#     total_target_capacity        = 1
#   }
#
#   tags = {
#     Name       = "${local.name_prefix}-fleet-instant"
#     TestNumber = "56"
#   }
# }

################################################################################
# Test 57: EC2 Fleet - maintain type with spot
################################################################################

resource "aws_launch_template" "for_fleet_spot" {
  name          = "${local.name_prefix}-lt-fleet-spot"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${local.name_prefix}-fleet-spot-instance"
      TestNumber = "57"
    }
  }
}

resource "aws_ec2_fleet" "maintain_spot" {
  type                               = "maintain"
  terminate_instances_with_expiration = true

  launch_template_config {
    launch_template_specification {
      launch_template_id = aws_launch_template.for_fleet_spot.id
      version            = "$Latest"
    }

    override {
      instance_type = "t2.micro"
      max_price     = "0.05"
    }

    override {
      instance_type = "t3.micro"
      max_price     = "0.05"
    }
  }

  target_capacity_specification {
    default_target_capacity_type = "spot"
    total_target_capacity        = 1
    spot_target_capacity         = 1
  }

  spot_options {
    allocation_strategy            = "lowestPrice"
    instance_interruption_behavior = "terminate"
  }

  tags = {
    Name       = "${local.name_prefix}-fleet-spot"
    TestNumber = "57"
  }
}

################################################################################
# Outputs
################################################################################

output "launch_templates" {
  value = {
    basic         = aws_launch_template.basic.id
    full          = aws_launch_template.full.id
    for_asg       = aws_launch_template.for_asg.id
    for_fleet     = aws_launch_template.for_fleet.id
    for_fleet_spot = aws_launch_template.for_fleet_spot.id
  }
  description = "Launch template IDs"
}

output "scaling_instances" {
  value = {
    from_launch_template         = aws_instance.from_launch_template.id
    from_launch_template_version = aws_instance.from_launch_template_version.id
  }
  description = "Scaling test instance IDs"
}

output "auto_scaling_groups" {
  value = {
    basic           = aws_autoscaling_group.basic.name
    with_scaling    = aws_autoscaling_group.with_scaling.name
    target_tracking = aws_autoscaling_group.with_target_tracking.name
  }
  description = "Auto Scaling Group names"
}

output "ec2_fleets" {
  value = {
    # instant commented out - Terraform doesn't support instant fleet deletion
    maintain_spot = aws_ec2_fleet.maintain_spot.id
  }
  description = "EC2 Fleet IDs"
}
