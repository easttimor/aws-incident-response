module "rule-disruption-inspector" {
  source = "../modules/rules"

  name          = "disruption-inspector"
  description   = "Capture Inspector configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.inspector"
    ],
    "detail": {
      "eventSource": [
        "inspector.amazonaws.com"
      ],
      "eventName": [
        "DeleteAssessmentRun",
        "DeleteAssessmentTarget",
        "DeleteAssessmentTemplate",
        "UnsubscribeFromEvent",
        "UpdateAssessmentTarget"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}