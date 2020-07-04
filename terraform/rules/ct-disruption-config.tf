module "rule-disruption-config" {
  source = "../modules/rules"

  name          = "disruption-config"
  description   = "Capture Config service configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.config"
    ],
    "detail": {
      "eventSource": [
        "config.amazonaws.com"
      ],
      "eventName": [
        "DeleteConfigRule",
        "DeleteConfigurationAggregator",
        "DeleteConfigurationRecorder",
        "DeleteConformancePack",
        "DeleteDeliveryChannel",
        "DeleteOrganizationConfigRule",
        "DeleteOrganizationConformancePack",
        "DeleteRemediationConfiguration",
        "DeleteRetentionConfiguration",
        "PutConfigRule",
        "PutConfigurationAggregator",
        "PutConformancePack",
        "PutDeliveryChannel",
        "PutOrganizationConfigRule",
        "PutOrganizationConformancePack",
        "PutRemediationConfigurations",
        "PutRemediationExceptions",
        "PutRetentionConfiguration",
        "StopConfigurationRecorder"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}