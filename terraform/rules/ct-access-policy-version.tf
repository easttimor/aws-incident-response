module "rule-access-policy-version" {
  source = "../modules/rules"

  name          = "access-policy-version"
  description   = "Capture IAM Policy version changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.iam"
    ],
    "detail": {
      "eventSource": [
        "iam.amazonaws.com"
      ],
      "eventName": [
        "CreatePolicyVersion", 
        "SetDefaultPolicyVersion"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
