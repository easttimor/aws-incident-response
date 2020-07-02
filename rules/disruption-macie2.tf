resource "aws_cloudwatch_event_rule" "this" {
  name        = "disruption-macie"
  description = "Capture Macie configuration changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.macie"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
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