
locals {
  # SNS

}

module "access-rootlogin" {
  source        = "./rules"
  sns_topic_arn = module.sns.sns_topic_arn
}

module "sns" {
  source = "./modules/sns_topic"
}