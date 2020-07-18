module "rule-data-ebs" {
  source = "../modules/rules"

  name          = "data-ebs"
  description   = "Capture EBS configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "ec2.amazonaws.com"
      ],
      "eventName": [
        "GetPasswordData",
        "ModifyImageAttribute",
        "ModifySnapshotAttribute"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}