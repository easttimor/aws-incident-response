resource "aws_cloudwatch_event_rule" "disruption-guardduty" {
  name        = "disruption-guardduty"
  description = "Capture GuardDuty configuration changes"

  event_pattern = <<PATTERN
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
}