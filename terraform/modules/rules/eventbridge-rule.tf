resource "aws_cloudwatch_event_rule" "this" {
  name          = var.name
  description   = var.description
  is_enabled    = var.is_enabled
  event_pattern = var.event_pattern
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.this.name
  target_id = "SendToSNS"
  arn       = var.sns_topic_arn
}
