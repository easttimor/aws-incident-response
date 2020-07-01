resource "aws_cloudwatch_event_rule" "this" {
  name        = "disruption-cloudtrail"
  description = "Capture CloudTrail configuration changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "DeleteTrail",
      "StopLogging",
      "UpdateTrail",
      "PutEventSelectors"
    ]
  }
}
PATTERN
}