module "rule-principal-policy-changes" {
  source = "../modules/rules"

  name          = "access-principal-policy-changes"
  description   = "Capture IAM Principal Policy association changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "eventName": [
      "AttachUserPolicy", 
      "DetachUserPolicy",
      "AttachRolePolicy", 
      "DetachRolePolicy",
      "PutUserPolicy",
      "PutGroupPolicy",
      "PutRolePolicy",
      "DeleteUserPolicy",
      "DeleteGroupPolicy",
      "DeleteRolePolicy",
      "DeleteRolePermissionsBoundary"
    ]
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}