resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-federation"
  description = "Capture IAM IdP configuration changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.iam"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "iam.amazonaws.com"
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
}