resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-principalpolicies"
  description = "Capture IAM Principal Policy association changes"

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
      "AttachUserPolicy", 
      "DetachUserPolicy",
      "AttachRolePolicy", 
      "DetachRolePolicy",
      "PutUserPolicy",
      "PutGroupPolicy",
      "PutRolePolicy",
      "DeleteUserPolicy",
      "DeleteGroupPolicy",
      "DeleteRolePolicy",
      "DeleteRolePermissionsBoundary"
    ]
  }
}
PATTERN
}

