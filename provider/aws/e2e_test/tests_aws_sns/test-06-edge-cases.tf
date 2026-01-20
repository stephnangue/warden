# test-06-edge-cases.tf
# Tests 39-45: SNS Edge Cases
# Tests: message attributes, data protection, archive policies

################################################################################
# Test 39: Topic for message attribute testing
################################################################################
resource "aws_sns_topic" "message_attrs" {
  name = "${local.name_prefix}-message-attrs"

  tags = {
    Name        = "Message Attrs Topic"
    TestNumber  = "39"
    Description = "Topic for message attribute testing"
  }
}

# Create SQS subscription to verify message attributes pass through
resource "aws_sqs_queue" "attrs_target" {
  name = "${local.name_prefix}-attrs-target"
  tags = { Name = "Attrs Target", TestNumber = "39" }
}

resource "aws_sqs_queue_policy" "attrs_target" {
  queue_url = aws_sqs_queue.attrs_target.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNS"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.attrs_target.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.message_attrs.arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "attrs" {
  topic_arn = aws_sns_topic.message_attrs.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.attrs_target.arn
}

################################################################################
# Test 40: Topic with data protection policy
################################################################################
resource "aws_sns_topic" "data_protection" {
  name = "${local.name_prefix}-data-protection"

  tags = {
    Name        = "Data Protection Topic"
    TestNumber  = "40"
    Description = "Topic with data protection policy"
  }
}

resource "aws_sns_topic_data_protection_policy" "main" {
  arn = aws_sns_topic.data_protection.arn

  policy = jsonencode({
    Name        = "data-protection-policy"
    Description = "Protect sensitive data"
    Version     = "2021-06-01"
    Statement = [
      {
        Sid            = "audit-all"
        DataDirection  = "Inbound"
        Principal      = ["*"]
        DataIdentifier = ["arn:aws:dataprotection::aws:data-identifier/CreditCardNumber"]
        Operation = {
          Audit = {
            SampleRate = "99"
            FindingsDestination = {}
          }
        }
      }
    ]
  })
}

################################################################################
# Test 41: Topic with signature version 2
################################################################################
resource "aws_sns_topic" "sig_v2" {
  name                   = "${local.name_prefix}-sig-v2"
  signature_version      = 2

  tags = {
    Name        = "Sig V2 Topic"
    TestNumber  = "41"
    Description = "Topic with signature version 2"
  }
}

################################################################################
# Test 42: Topic with tracing config
################################################################################
resource "aws_sns_topic" "tracing" {
  name           = "${local.name_prefix}-tracing"
  tracing_config = "Active"

  tags = {
    Name        = "Tracing Topic"
    TestNumber  = "42"
    Description = "Topic with X-Ray tracing enabled"
  }
}

################################################################################
# Test 43: Topic with passthrough tracing
################################################################################
resource "aws_sns_topic" "passthrough_tracing" {
  name           = "${local.name_prefix}-passthrough-trace"
  tracing_config = "PassThrough"

  tags = {
    Name        = "Passthrough Tracing Topic"
    TestNumber  = "43"
    Description = "Topic with passthrough tracing"
  }
}

################################################################################
# Test 44: FIFO topic with all features
################################################################################
resource "aws_sns_topic" "fifo_full" {
  name                        = "${local.name_prefix}-fifo-full.fifo"
  fifo_topic                  = true
  content_based_deduplication = true
  display_name                = "Full Featured FIFO"
  kms_master_key_id           = "alias/aws/sns"

  tags = {
    Name        = "Full FIFO Topic"
    TestNumber  = "44"
    Description = "FIFO topic with all features enabled"
  }
}

################################################################################
# Test 45: Standard topic with all features
################################################################################
resource "aws_sns_topic" "standard_full" {
  name              = "${local.name_prefix}-standard-full"
  display_name      = "Full Featured Standard"
  kms_master_key_id = "alias/aws/sns"
  tracing_config    = "Active"
  signature_version = 2

  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 20
        maxDelayTarget     = 20
        numRetries         = 3
        backoffFunction    = "linear"
      }
    }
  })

  tags = {
    Name        = "Full Standard Topic"
    TestNumber  = "45"
    Description = "Standard topic with all features enabled"
  }
}

################################################################################
# Outputs
################################################################################

output "edge_case_topics" {
  value = {
    message_attrs       = aws_sns_topic.message_attrs.name
    data_protection     = aws_sns_topic.data_protection.name
    sig_v2              = aws_sns_topic.sig_v2.name
    tracing             = aws_sns_topic.tracing.name
    passthrough_tracing = aws_sns_topic.passthrough_tracing.name
    fifo_full           = aws_sns_topic.fifo_full.name
    standard_full       = aws_sns_topic.standard_full.name
  }
  description = "Edge case topic names"
}

output "edge_case_topic_arns" {
  value = {
    message_attrs   = aws_sns_topic.message_attrs.arn
    data_protection = aws_sns_topic.data_protection.arn
    fifo_full       = aws_sns_topic.fifo_full.arn
    standard_full   = aws_sns_topic.standard_full.arn
  }
  description = "Edge case topic ARNs"
}

output "attrs_target_queue" {
  value       = aws_sqs_queue.attrs_target.url
  description = "Attrs target queue URL"
}
