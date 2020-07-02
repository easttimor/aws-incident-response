module "rule-access-consolelogin" {
  source = "../modules/rules"

  name          = "access-root-console-login"
  description   = "Capture ConsoleLogin from Root account"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.signin"
    ],
    "detail": {
      "eventSource": [
        "signin.amazonaws.com"
      ],
      "eventName": [
        "ConsoleLogin"
      ],
      "eventType": [
        "AwsConsoleSignIn"
      ],
      "userIdentity": {
          "type": ["Root"]
      }
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}