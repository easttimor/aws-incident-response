module "rule-access-credentials" {
  source = "../modules/rules"

  name          = "access-credentials"
  description   = "Capture IAM credential updates"
  is_enabled    = true
  event_pattern = <<-PATTERN
  {
    "detail": {
      "eventSource": [
        "iam.amazonaws.com"
      ],
      "eventName": [
        "CreateAccessKey", 
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "CreateVirtualMFADevice",
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "EnableMFADevice",
        "CreateServiceSpecificCredential",
        "UpdateServiceSpecificCredential",
        "DeleteServiceSpecificCredential",
        "UploadServerCertificate",
        "DeleteServerCertificate",
        "UploadSigningCertificate",
        "UpdateSigningCertificate",
        "DeleteSigningCertificate",
        "UploadSSHPublicKey",
        "UpdateSSHPublicKey",
        "DeleteSSHPublicKey"
      ]
    }
  }
  PATTERN
  sns_topic_arn = var.sns_topic_arn
}
