module "rule-network-gateway" {
  source = "../modules/rules"

  name          = "network-gateway"
  description   = "Capture network gateway configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.ec2"
    ],
    "detail": {
      "eventName": [
        "CreateCustomerGateway",
        "DeleteCustomerGateway",
        "AttachInternetGateway",
        "CreateInternetGateway",
        "DeleteInternetGateway",
        "DetachInternetGateway"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
