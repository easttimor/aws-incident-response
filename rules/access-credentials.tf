resource "aws_cloudwatch_event_rule" "this" {
  name        = "access-credentials"
  description = "Capture IAM credential changes"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.iam"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
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
      "EnableMFADevice"
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
}
