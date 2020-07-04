module "rule-disruption-access-analyzer" {
  source = "../modules/rules"

  name          = "disruption-access-analyzer"
  description   = "Capture Access Analyzer service configuration changes and findings updates"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "access-analyzer.amazonaws.com"
      ],
      "eventName": [
        "CreateArchiveRule",
        "DeleteAnalyzer",
        "UpdateArchiveRule",
        "UpdateFindings"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}