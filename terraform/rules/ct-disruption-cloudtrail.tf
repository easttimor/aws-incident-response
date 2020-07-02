resource "aws_cloudwatch_event_rule" "disruption-cloudtrail" {
  name        = "disruption-cloudtrail"
  description = "Capture CloudTrail configuration changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.cloudtrail"
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