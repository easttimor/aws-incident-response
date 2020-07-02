module "rule-access-trustpolicy" {
  source = "../modules/rules"

  name          = "access-trustpolicy"
  description   = "Capture IAM trust policy configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
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
  sns_topic_arn = var.sns_topic_arn
}