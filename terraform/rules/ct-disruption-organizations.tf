module "rule-disruption-organizations" {
  source = "../modules/rules"

  name          = "disruption-organizations"
  description   = "Capture Orgainizations configuration deletion"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "organizations.amazonaws.com"
      ],
      "eventName": [
        "DeletePolicy",
        "DeregisterDelegatedAdministrator",
        "LeaveOrganization",
        "MoveAccount",
        "RemoveAccountFromOrganization",
        "UpdateOrganizationalUnit",
        "UpdatePolicy"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
