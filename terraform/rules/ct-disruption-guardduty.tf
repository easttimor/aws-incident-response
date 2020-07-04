module "rule-disruption-guardduty" {
  source = "../modules/rules"

  name          = "disruption-guardduty"
  description   = "Capture GuardDuty configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.guardduty"
    ],
    "detail": {
      "eventSource": [
        "guardduty.amazonaws.com"
      ],
      "eventName": [
        "CreateFilter",
        "CreateIPSet",
        "DeleteDetector",
        "DeleteMembers",
        "DeletePublishingDestination",
        "DeleteThreatIntelSet",
        "DisassociateFromMasterAccount",
        "DisassociateMembers",
        "StopMonitoringMembers",
        "UpdateDetector",
        "UpdateFilter",
        "UpdateIPSet",
        "UpdatePublishingDestination",
        "UpdateThreatIntelSet"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}