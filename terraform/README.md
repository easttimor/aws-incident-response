# Approach
This project is only a reference implementation. These event filters could be applied numerous ways. Other options that may better suit your environment include:
* CloudWatch Logs Metric Filters and Alarms... if your CloudTrail logs are in CloudWatch Logs
* commercial solutions like ElasticSearch and Splunk
* ad-hoc or scheduled Athena queries, which is how this whole project started

## One way to provision this:

1. Create an S3 Bucket in the target account that will hold the configuration state. 
* Set that value in: ```terraform/terragrunt.hcl```

2. Become a caller principal for your target account. I use ```https://github.com/easttimor/aws-scripts/aws_cli_assumerole.sh```

3. Initialize Terraform/Terragrunt
```
$ terragrunt init
```
3. Run your plan
```
$ terragrunt plan
...
Remote state S3 bucket aws-incident-response-tfstate does not exist or you don't have permissions to access it. Would you like Terragrunt to create it? (y/n) y\
...
Plan: 10 to add, 0 to change, 0 to destroy.

------------------------------------------------------------------------

Note: You didn't specify an "-out" parameter to save this plan, so Terraform
can't guarantee that exactly these actions will be performed if
"terraform apply" is subsequently run.
```

4. Run your apply if everything looks good
```
$ terragrunt apply
...
Plan: 1 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes
...
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.
```
