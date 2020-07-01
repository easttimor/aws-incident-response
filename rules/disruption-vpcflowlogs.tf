resource "aws_cloudwatch_event_rule" "this" {
  name        = "disruption-vpcflowlogs"
  description = "Capture VPC Flow Log configuration deletion"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
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
}