resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-policyversion"
  description = "Capture IAM Policy version changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.iam"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "iam.amazonaws.com"
    ],
    "eventName": [
      "CreatePolicyVersion", 
      "SetDefaultPolicyVersion"
    ]
  }
}
PATTERN
}
