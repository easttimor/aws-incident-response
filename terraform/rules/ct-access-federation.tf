module "rule-access-federation" {
  source = "../modules/rules"

  name          = "access-federation"
  description   = "Capture IAM IdP configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "source": [
        "aws.iam"
      ],
      "eventName": [
        "CreateSAMLProvider",
        "UpdateSAMLProvider",
        "DeleteSAMLProvider",
        "CreateOpenIDConnectProvider",
        "DeleteOpenIDConnectProvider",
        "UpdateOpenIDConnectProviderThumbprint",
        "AddClientIDToOpenIDConnectProvider",
        "RemoveClientIDFromOpenIDConnectProvider"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
