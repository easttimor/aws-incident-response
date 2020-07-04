module "rule-disruption-cloudwatch" {
  source = "../modules/rules"

  name          = "disruption-cloudwatch"
  description   = "Capture CloudWatch service configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.events",
      "aws.cloudwatch",
      "aws.monitoring"
    ],
    "detail": {
      "eventSource": [
        "monitoring.amazonaws.com",
        "events.amazonaws.com"
      ],
      "eventName": [
        "DeleteAlarms",
        "DeleteAnomalyDetector",
        "DeleteInsightRules",
        "PutAnomalyDetector",
        "PutInsightRule",
        "PutMetricAlarm",
        "DeleteRule",
        "DisableAlarmActions"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}