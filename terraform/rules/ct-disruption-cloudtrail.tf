module "rule-disruption-cloudtrail" {
  source = "../modules/rules"

  name          = "disruption-cloudtrail"
  description   = "Capture CloudTrail configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
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
  sns_topic_arn = var.sns_topic_arn
}