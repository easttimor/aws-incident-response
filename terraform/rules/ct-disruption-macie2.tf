module "rule-disruption-macie2" {
  source = "../modules/rules"

  name          = "disruption-macie2"
  description   = "Capture Macie configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.macie"
    ],
    "detail": {
      "eventSource": [
        "macie2.amazonaws.com"
      ],
      "eventName": [
        "ArchiveFindings",
        "CreateFindingsFilter",
        "DeleteMember",
        "DisassociateFromMasterAccount",
        "DisassociateMember",
        "DisableMacie",
        "UpdateFindingsFilter",
        "UpdateMacieSession",
        "UpdateMemberSession",
        "DisableOrganizationAdminAccount",
        "UpdateClassificationJob",
        "UpdateFindingsFilter"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}