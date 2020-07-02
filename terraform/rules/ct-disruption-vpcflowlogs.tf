module "rule-disruption-vpcflowlogs" {
  source = "../modules/rules"

  name          = "disruption-vpcflowlogs"
  description   = "Capture VPC Flow Log configuration deletion"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.ec2"
    ],
    "detail": {
      "eventSource": [
        "ec2.amazonaws.com"
      ],
      "eventName": [
        "DeleteFlowLogs"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}