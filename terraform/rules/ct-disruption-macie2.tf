resource "aws_cloudwatch_event_rule" "disruption-macie2" {
  name        = "disruption-macie2"
  description = "Capture Macie configuration changes"

  event_pattern = <<PATTERN
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
}