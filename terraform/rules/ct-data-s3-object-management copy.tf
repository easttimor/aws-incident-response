module "rule-data-s3-object-management" {
  source = "../modules/rules"

  name          = "data-object-management"
  description   = "Capture S3 object management configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "s3.amazonaws.com"
      ],
      "eventName": [
        "PutBucketLogging",
        "PutBucketWebsite",
        "PutEncryptionConfiguration",
        "PutLifecycleConfiguration",
        "PutReplicationConfiguration",
        "ReplicateObject",
        "RestoreObject"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}