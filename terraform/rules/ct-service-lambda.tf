module "rule-service-lambda" {
  source = "../modules/rules"

  name          = "service-lambda"
  description   = "Capture high risk Lambda events"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.lambda"
    ],
    "detail": {
      "eventName": [
        "AddLayerVersionPermission",
        "AddPermission",
        "PublishLayerVersion",
        "PublishVersion",
        "UpdateFunctionCode"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
