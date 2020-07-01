resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-rootlogin"
  description = "Capture ConsoleLogin from Root account"

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
      "ConsoleLogin"
    ]
    "userIdentity": {
        "type": "Root"
    }
  }
}
PATTERN
}