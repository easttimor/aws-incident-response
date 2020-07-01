resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-trustpolicy"
  description = "Capture IAM trust policy configuration changes"

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
      "UpdateAssumeRolePolicy"
    ]
  }
}
PATTERN
}