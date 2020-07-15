module "rule-network-mirror" {
  source = "../modules/rules"

  name          = "network-mirror"
  description   = "Capture traffic mirror configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.ec2"
    ],
    "detail": {
      "eventName": [
        "CreateTrafficMirrorFilter",
        "CreateTrafficMirrorFilterRule",
        "CreateTrafficMirrorSession",
        "CreateTrafficMirrorTarget"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
