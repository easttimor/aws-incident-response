module "rule-data-s3-permissions" {
  source = "../modules/rules"

  name          = "data-s3-permissions"
  description   = "Capture S3 permissions configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "s3.amazonaws.com"
      ],
      "eventName": [
        "PutAccessPointPolicy",
        "PutAccountPublicAccessBlock",
        "PutBucketAcl",
        "PutBucketCORS",
        "PutBucketPolicy",
        "PutBucketPublicAccessBlock",
        "PutObjectAcl"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}