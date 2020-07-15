module "rule-access-root-account-activity" {
  source = "../modules/rules"

  name          = "access-root-account-activity"
  description   = "Capture all API activity from Root account"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventName": [
        "*"
      ],
      "userIdentity": {
          "type": ["Root"]
      }
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}