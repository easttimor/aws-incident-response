module "rule-disruption-security-hub" {
  source = "../modules/rules"

  name          = "disruption-security-hub"
  description   = "Capture Security Hub configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "securityhub.amazonaws.com"
      ],
      "eventName": [
        "BatchDisableStandards",
        "DeleteActionTarget",
        "DeleteMembers",
        "DisableImportFindingsForProduct",
        "DisableSecurityHub",
        "DisassociateFromMasterAccount",
        "DisassociateMembers",
        "UpdateActionTarget",
        "UpdateStandardsControl"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
