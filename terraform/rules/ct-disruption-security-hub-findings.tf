module "rule-disruption-security-hub-findings" {
  source = "../modules/rules"

  name          = "disruption-security-hub-findings"
  description   = "Capture Security Hub Findings changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "securityhub.amazonaws.com"
      ],
      "eventName": [
        "BatchUpdateFindings",
        "DeleteInsight",
        "UpdateFindings",
        "UpdateInsight"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
