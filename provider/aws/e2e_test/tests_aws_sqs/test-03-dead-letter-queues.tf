# test-03-dead-letter-queues.tf
# Tests 21-28: Dead Letter Queue configurations
# Tests: DLQ setup, redrive policies, standard and FIFO DLQs

################################################################################
# Test 21: Dead Letter Queue (Standard)
################################################################################
resource "aws_sqs_queue" "dlq_standard" {
  name = "${local.name_prefix}-dlq-standard"

  tags = {
    Name        = "Standard DLQ"
    TestNumber  = "21"
    Description = "Standard dead letter queue"
  }
}

################################################################################
# Test 22: Source Queue with DLQ redrive policy
################################################################################
resource "aws_sqs_queue" "with_dlq" {
  name = "${local.name_prefix}-with-dlq"

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq_standard.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name        = "Queue with DLQ"
    TestNumber  = "22"
    Description = "Queue with dead letter queue configured"
  }
}

################################################################################
# Test 23: DLQ with higher max receive count
################################################################################
resource "aws_sqs_queue" "dlq_high_receive" {
  name = "${local.name_prefix}-dlq-high-receive"

  tags = {
    Name        = "High Receive DLQ"
    TestNumber  = "23"
    Description = "DLQ target for high receive count"
  }
}

resource "aws_sqs_queue" "high_receive_source" {
  name = "${local.name_prefix}-high-receive-source"

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq_high_receive.arn
    maxReceiveCount     = 10
  })

  tags = {
    Name        = "High Receive Source"
    TestNumber  = "23"
    Description = "Source queue with high max receive count"
  }
}

################################################################################
# Test 24: DLQ with minimum max receive count
################################################################################
resource "aws_sqs_queue" "dlq_min_receive" {
  name = "${local.name_prefix}-dlq-min-receive"

  tags = {
    Name        = "Min Receive DLQ"
    TestNumber  = "24"
    Description = "DLQ target for minimum receive count"
  }
}

resource "aws_sqs_queue" "min_receive_source" {
  name = "${local.name_prefix}-min-receive-source"

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq_min_receive.arn
    maxReceiveCount     = 1
  })

  tags = {
    Name        = "Min Receive Source"
    TestNumber  = "24"
    Description = "Source queue with minimum max receive count"
  }
}

################################################################################
# Test 25: FIFO Dead Letter Queue
################################################################################
resource "aws_sqs_queue" "dlq_fifo" {
  name       = "${local.name_prefix}-dlq.fifo"
  fifo_queue = true

  tags = {
    Name        = "FIFO DLQ"
    TestNumber  = "25"
    Description = "FIFO dead letter queue"
  }
}

################################################################################
# Test 26: FIFO Queue with FIFO DLQ
################################################################################
resource "aws_sqs_queue" "fifo_with_dlq" {
  name       = "${local.name_prefix}-fifo-with-dlq.fifo"
  fifo_queue = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq_fifo.arn
    maxReceiveCount     = 5
  })

  tags = {
    Name        = "FIFO with DLQ"
    TestNumber  = "26"
    Description = "FIFO queue with dead letter queue"
  }
}

################################################################################
# Test 27: DLQ with redrive allow policy (allow all)
################################################################################
resource "aws_sqs_queue" "dlq_allow_all" {
  name = "${local.name_prefix}-dlq-allow-all"

  tags = {
    Name        = "DLQ Allow All"
    TestNumber  = "27"
    Description = "DLQ with allow all redrive policy"
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "allow_all" {
  queue_url = aws_sqs_queue.dlq_allow_all.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "allowAll"
  })
}

################################################################################
# Test 28: DLQ with redrive allow policy (specific queues)
################################################################################
resource "aws_sqs_queue" "dlq_allow_specific" {
  name = "${local.name_prefix}-dlq-allow-specific"

  tags = {
    Name        = "DLQ Allow Specific"
    TestNumber  = "28"
    Description = "DLQ with specific source queue allow policy"
  }
}

resource "aws_sqs_queue" "specific_source" {
  name = "${local.name_prefix}-specific-source"

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq_allow_specific.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name        = "Specific Source"
    TestNumber  = "28"
    Description = "Source queue for specific DLQ"
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "allow_specific" {
  queue_url = aws_sqs_queue.dlq_allow_specific.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.specific_source.arn]
  })
}

################################################################################
# Outputs
################################################################################

output "dlq_queues" {
  value = {
    standard         = aws_sqs_queue.dlq_standard.name
    with_dlq         = aws_sqs_queue.with_dlq.name
    high_receive_dlq = aws_sqs_queue.dlq_high_receive.name
    high_receive_src = aws_sqs_queue.high_receive_source.name
    min_receive_dlq  = aws_sqs_queue.dlq_min_receive.name
    min_receive_src  = aws_sqs_queue.min_receive_source.name
    fifo_dlq         = aws_sqs_queue.dlq_fifo.name
    fifo_with_dlq    = aws_sqs_queue.fifo_with_dlq.name
    allow_all        = aws_sqs_queue.dlq_allow_all.name
    allow_specific   = aws_sqs_queue.dlq_allow_specific.name
    specific_source  = aws_sqs_queue.specific_source.name
  }
  description = "Dead letter queue names"
}

output "dlq_urls" {
  value = {
    standard       = aws_sqs_queue.dlq_standard.url
    with_dlq       = aws_sqs_queue.with_dlq.url
    fifo_dlq       = aws_sqs_queue.dlq_fifo.url
    fifo_with_dlq  = aws_sqs_queue.fifo_with_dlq.url
  }
  description = "Dead letter queue URLs"
}

output "dlq_arns" {
  value = {
    standard = aws_sqs_queue.dlq_standard.arn
    fifo     = aws_sqs_queue.dlq_fifo.arn
  }
  description = "Dead letter queue ARNs"
}
