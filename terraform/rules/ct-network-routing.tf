module "rule-network-routing" {
  source = "../modules/rules"

  name          = "network-routing"
  description   = "Capture network routing configuration changes"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "source": [
      "aws.ec2"
    ],
    "detail": {
      "eventName": [
        "CreateRoute",
        "CreateRouteTable",
        "DeleteRouteTable",
        "DeleteRoute",
        "DisassociateRouteTable",
        "ReplaceRoute",
        "ReplaceRouteTableAssociation"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
