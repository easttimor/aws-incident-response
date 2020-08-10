# AWS Incident Response 
Investigation of API activity using Athena
and notification of actions using EventBridge

## Use
For a *slighly* more pleasant viewing experience, use the GitHub pages link: https://easttimor.github.io/aws-incident-response/

For those on GitHub Pages already, the repo additionally contains Terraform resources for deploying Event Rules to catch high risk API events.

## Introduction
This project explores useful CloudTrail events that support incident response and detection of misconfigurations. Documenting the queries and filters used to identify these CloudTrail events helps to:

* build a timeline of events
* understand the scope of the incident
* identify indicators of compromise
* decrease time to containment and recovery

Mis-configurations are important events to identify early. These configurations may introduce a vulnerability, but may also be an indicator of compromise. 

Whether executed manually or by automating, this information may be used to develop incident response playbooks. These types of formalization activities promote a consistent, efficient, and effective response to security incidents. 

**NEW 2020-08-04** Addition of VPC Flow Log queries via Athena

Table of Contents
=================

   * [AWS Incident Response](#aws-incident-response)
      * [Introduction](#introduction)
   * [Table of Contents](#table-of-contents)
      * [Why Athena?](#why-athena)
         * [Getting Started](#getting-started)
         * [Alternatives](#alternatives)
      * [Why EventBridge?](#why-eventbridge)
   * [Incidents](#incidents)
      * [General IAM Investigation](#general-iam-investigation)
         * [API Errors](#api-errors)
         * [Activity from potentially malicious source ip](#activity-from-potentially-malicious-source-ip)
         * [S3 ListBuckets](#s3-listbuckets)
      * [Incident: Access Key Exposure](#incident-access-key-exposure)
         * [Find the IAM Principal and AWS Account associated with Access Key](#find-the-iam-principal-and-aws-account-associated-with-access-key)
         * [All key usage](#all-key-usage)
         * [Activity for a specific IAM User](#activity-for-a-specific-iam-user)
         * [Look for user agent anomalies for key](#look-for-user-agent-anomalies-for-key)
         * [Look for source ip anomalies](#look-for-source-ip-anomalies)
      * [Incident: EC2 Instance Compromise](#incident-ec2-instance-compromise)
         * [Recent API calls with a specific instanceId as the target resource](#recent-api-calls-with-a-specific-instanceid-as-the-target-resource)
         * [EC2 Instance profile - most frequent API calls](#ec2-instance-profile---most-frequent-api-calls)
         * [EC2 Instance profile - most denied API calls](#ec2-instance-profile---most-denied-api-calls)
         * [All EC2 Instance Profiles - most denied instance profiles](#all-ec2-instance-profiles---most-denied-instance-profiles)
         * [All EC2 Instance Profiles - most denied event names](#all-ec2-instance-profiles---most-denied-event-names)
         * [EC2 Instance Profile interacting with IAM](#ec2-instance-profile-interacting-with-iam)
         * [EC2 Instance Profile enumerating S3](#ec2-instance-profile-enumerating-s3)
      * [General Purpose Queries](#general-purpose-queries)
         * [Most common API actions for a given day](#most-common-api-actions-for-a-given-day)
         * [Most common error codes](#most-common-error-codes)
            * [Principals getting denied the most](#principals-getting-denied-the-most)
         * [Common denied actions from specific principal (see above)](#common-denied-actions-from-specific-principal-see-above)
   * [API Watchlist](#api-watchlist)
      * [IAM](#iam)
         * [Root Credential Use](#root-credential-use)
         * [Remove MFA from an IAM User](#remove-mfa-from-an-iam-user)
         * [All IAM Changes](#all-iam-changes)
         * [Creation of IAM Principals](#creation-of-iam-principals)
         * [Privilege Escalation: IAM Policy](#privilege-escalation-iam-policy)
         * [Add/Update Credentials](#addupdate-credentials)
         * [Privilege Escalation: Adding permissions](#privilege-escalation-adding-permissions)
         * [Privilege Escalation: Expand Access to an IAM Role](#privilege-escalation-expand-access-to-an-iam-role)
         * [Modify Federated Access](#modify-federated-access)
      * [S3](#s3)
      * [EC2](#ec2)
         * [General](#general)
         * [EBS Encryption Account-wide Setting](#ebs-encryption-account-wide-setting)
         * [Share EBS Snapshot](#share-ebs-snapshot)
         * [Modify UserData](#modify-userdata)
         * [Network Access](#network-access)
         * [Traffic Mirroring](#traffic-mirroring)
         * [Network Routing](#network-routing)
      * [Lambda](#lambda)
      * [Disruption and Evasion](#disruption-and-evasion)
         * [CloudTrail](#cloudtrail)
            * [CloudTrail Disruption](#cloudtrail-disruption)
         * [Config](#config)
            * [Disrupt Config Recording, Evaluation, and Remediation](#disrupt-config-recording-evaluation-and-remediation)
         * [GuardDuty](#guardduty)
            * [GuardDuty Disruption](#guardduty-disruption)
            * [GuardDuty Recon](#guardduty-recon)
         * [IAM Access Analyzer](#iam-access-analyzer)
         * [Inspector](#inspector)
         * [Macie(2)](#macie2)
         * [EC2](#ec2-1)
            * [Disrupt VPC Flow Logs](#disrupt-vpc-flow-logs)
         * [S3](#s3-1)
            * [Permissions Update](#permissions-update)
            * [Data Management](#data-management)
         * [SecurityHub](#securityhub)
            * [Terminology](#terminology)
            * [API Actions](#api-actions)
            * [SecurityHub Service Disruption](#securityhub-service-disruption)
            * [SecurityHub Findings Disruption](#securityhub-findings-disruption)
         * [Web Application Firewall (WAF)](#web-application-firewall-waf)
   * [Network Flow Analysis](#network-flow-analysis)
      * [Manual Setup](#manual-setup)
         * [Add table to Athena](#add-table-to-athena)
         * [Add date partition](#add-date-partition)
      * [Useful Queries](#useful-queries)
         * [General concepts](#general-concepts)
         * [Inbound Traffic](#inbound-traffic)
            * [Accepted packets by port](#accepted-packets-by-port)
            * [Rejected packets by port](#rejected-packets-by-port)
            * [Volume by sourceaddress](#volume-by-sourceaddress)
            * [Volume by destinationport](#volume-by-destinationport)
         * [Outbound Traffic](#outbound-traffic)
            * [Volume by desination](#volume-by-desination)
            * [Volume by port](#volume-by-port)
            * [Rejected by port](#rejected-by-port)
            * [Rejected by destination](#rejected-by-destination)
         * [Example: Connectionless LDAP Reflection Attack](#example-connectionless-ldap-reflection-attack)
   * [Useful CloudTrail fields](#useful-cloudtrail-fields)
   * [Credit and References](#credit-and-references)


## Why Athena?
CloudTrail logs should be stored and archived in S3, where they are essentially useless unless integrated with another product or service. Amazon Athena allows you to query these JSON-formatted logs using standard SQL. This approach gives access to a potentially massive amount of CloudTrail data without the cost and effort of implementing Splunk, ElasticSearch, or storing in another database.

### Getting Started
Athena charges for the data scanned for each query. You may only return one record, but will be charged for all data queried to match that record. By default, S3 data is not indexed, so Athena will inefficiently scan a LOT of data. There are also S3 charges (GET requests) that factor in at larger scale. 
> https://aws.amazon.com/athena/pricing/

**But, we can make Athena faster and cost effective by creating partitions.**
Implement CloudTrail Partitioner. By default, Partitioner will create a virtual table for each AWS account so you don't scan an entire aggregated bucket. Partitioner will also add the following partitions:
* region
* year
* month
* day

Including these partitions in your SQL statements, as shown throughout this project, significantly improves query performance by limiting the amount of data scanned. Limiting the amount of data scanned saves money. For ad-hoc queries, such as those used for incident response, this cost is negligible. 
> https://github.com/duo-labs/cloudtrail-partitioner

### Alternatives
* query direct from CloudTrail: no cost, very limiting query syntax
* query direct from CloudWatch Logs: higher cost than S3, fast query performance but weaker query syntax
* ingest logs in Splunk, ElasticSearch, etc: expensive

## Why EventBridge?
> EventBridge builds on CloudWatch Events and uses the same APIs. This is essentially CloudWatch Events.

Querying CloudTrail, even if automated, is best suited for ad-hoc **response** to finding misconfigurations and investigating incidents. Many of these configuration-related indicators of compromise can be detected in near real time. EventBridge allows for these pre-defined CloudTrail events to be filtered and integrated with numerous alerting methods (e.g. SNS) and event flows (e.g. Lambda, 3rd party SIEM).

This approach is independent of the Athena queries, but both approaches complement each other.

The Terraform section of this project repo includes deployable event filters with a basic SNS notification. Where applicable, Athena queries on this page are reflected in these event filters.

EventBridge is cheap for this use case.
> https://aws.amazon.com/eventbridge/pricing/

# Incidents
The following section builds a collection of common incidents and the Athena queries that may prove useful in response. These queries attempt to explain timeline, scope,  impact, and surface indicators of compromise. 

## General IAM Investigation
> Some of the queries in this section were inspired by the following
> Reference: https://wellarchitectedlabs.com/security/300_labs/300_incident_response_with_aws_console_and_cli/2_iam/

### API Errors
```
select eventTime, eventSource, eventName, errorCode, errorMessage, responseElements, awsRegion, userIdentity.arn, sourceIPAddress, userAgent
from from cloudtrail_000000000000
and year = '####' and month = '##'
and errorCode in ('Client.UnauthorizedOperation','Client.InvalidPermission.NotFound','Client.OperationNotPermitted','AccessDenied')
order by eventTime desc
limit 25
```

### Activity from potentially malicious source ip
```
select eventTime, eventSource, eventName, awsRegion, userIdentity.arn, sourceIPAddress, userAgent
from from cloudtrail_000000000000
and year = '####' and month = '##'
and sourceIPAddress = 'x.x.x.x'
order by eventTime desc
limit 25
```

### S3 ListBuckets 
The ListBuckets API action, used to enumerate buckets within an AWS account, is a potential indicator of compromise.
```
select eventTime, eventSource, eventName, awsRegion, errorCode, errorMessage, userIdentity.arn, sourceIPAddress, userAgent
from from cloudtrail_000000000000
and year = '####' and month = '##'
and eventName = 'ListBuckets'
limit 25
```

## Incident: Access Key Exposure
We are looking for the following:
* what actions has this key been used for, historically and currently?
* has this key been used from any odd locations?
* has this key been used from any odd user agents?
* dig for any signs of established persistence to include or data access

These queries must include all AWS Regions.

### Find the IAM Principal and AWS Account associated with Access Key
```
select useridentity.principalId, useridentity.arn, useridentity.accountId, region
from cloudtrail_000000000000
where year = '####' and month = '##'
and useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
limit 1
```

### All key usage
Looking for high risk events that indicate establishing persistence, escalating permissions, resource creation (denial-of-wallet), data access (exfiltration). These actions may include:
* iam:CreateUser
* iam:CreateAccessKey
* iam:CreateLoginProfile
* iam:UpdateLoginProfile

Pay attention to all actions identified for priviledge escalation in this document.
```
select eventtime, eventsource, eventname, sourceipaddress, errorcode, useragent
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####' and month = '##'
```

### Activity for a specific IAM User
`userIdentity.arn` determined from the above query.
```
select eventtime, eventsource, eventname, errorcode, sourceipaddress, useragent
from cloudtrail_000000000000
where year = '####' and month = '##'
and userIdentity.arn = 'arn:aws:iam::000000000000:user/xxxxxxxx'
order by eventtime desc
```

Limit some noise.
```
select eventtime, eventsource, eventname, errorcode, sourceipaddress, useragent
from cloudtrail_000000000000
where year = '####' and month = '##'
and userIdentity.arn = 'arn:aws:iam::000000000000:user/xxxxxxxx'
and eventName not like 'Describe%'
and eventName not like 'List%'
and eventName not like 'Get%'
order by eventtime desc
```

### Look for user agent anomalies for key
Determine "normal" for user agent string
```
select useragent, count(*) as total
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####' and month = '##'
group by useragent
order by total desc
```

Assess activity for a specific user agent string; Conditions may be added to limit to a specific user or credential.
```
select eventtime, eventsource, eventname, sourceipaddress, errorcode
from cloudtrail_000000000000
where year = '####' and month = '##'
and useragent = 'seeAbove'
```

Group by user to include all access for a single user. This approach would be helpful if keys are rotated or a console login is used.
> This value format is for an IAM user and not an assumed role

```
select useragent, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##'
and userIdentity.userName = 'xxxxxx'
group by useragent
order by total desc
```

### Look for source ip anomalies
Group by sourceIpAddress for a specific access key.

```
select sourceipaddress, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##'
and useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
group by sourceipaddress
order by total desc
```

Assess all activity for a specific source IP, typically one believed to be an adversary in the case of a compromised key.
```
select eventtime, eventsource, eventname, errorcode, useragent
from cloudtrail_000000000000
where sourceipaddress = 'seeAbove'
and year = '####'
and month = '##'
```

Group by user to include multiple credentials for a single user. This approach would be helpful if keys are rotated or a console login is used.
> This value format is for an IAM user and not an assumed role
```
select sourceipaddress, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##'
and userIdentity.userName = 'xxxxxx'
group by sourceipaddress
order by total desc
```

## Incident: EC2 Instance Compromise
EC2 instances may have an IAM Role attached to them. The combination of the instance and the role is called an "instance profile". When the role is assumed, the EC2 instance ID is used as the session name part of the Principal ARN in CloudTrail. We can identify actions of EC2 instances using the clause ```useridentity.principalid like '%:i-%'``` or a specific EC2 instance ```useridentity.principalid like '%:i-00000000000000000'```

The actions of EC2 instances will typically be repetitive and persistent, because all actions are presumed to be initiated by software and not a human. Play close attention to any anomalous API calls. An attacker with access to an EC2 instance has access to any IAM permissions granted to that instance via the instance profile.

### Recent API calls with a specific instanceId as the target resource
> Very inefficient I know - room for improvement here

> The CloudTrail UI provides `resource name` as search criteria. Note that `resource name` is not an actual key in the JSON so they're abstracting some query magic. Relevant events may not be included in this CloudTrail API query - otherwise stated, the below Athena query will show you more events for better or worse.

```
select eventTime, eventName, eventSource, userIdentity.arn
from cloudtrail_000000000000
where year = 'xxxx' and month = 'xx' and day = 'xx'
and (requestParameters like '%i-xxxxxxxxxxxxxxxxx%' or responseElements like '%i-xxxxxxxxxxxxxxxxx%')
and eventname not like 'Describe%'
and eventsource = 'ec2.amazonaws.com'
limit 25
```

### EC2 Instance profile - most frequent API calls
```
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc
limit 25
```

### EC2 Instance profile - most denied API calls 
```
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-xxxxxxxxxxxxxxxxx'
and errorcode = 'AccessDenied'
group by eventname
order by total desc
limit 25
```

### All EC2 Instance Profiles - most denied instance profiles
```
select useridentity.principalid, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and errorcode = 'AccessDenied'
group by useridentity.principalid
order by total desc
limit 25
```

### All EC2 Instance Profiles - most denied event names
```
select eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventname <> 'AssumeRole'
and errorcode = 'AccessDenied'
group by eventsource,eventname
order by total desc
limit 25
```

### EC2 Instance Profile interacting with IAM
EC2 instances rarely have a need for IAM actions. Include an `and eventname <>` clause if legitimate actions are found that muddy the search results.
```
select useridentity.principalid,eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventsource = 'iam.amazonaws.com'
group by useridentity.principalid,eventsource,eventname
order by total desc
limit 25
```

### EC2 Instance Profile enumerating S3
EC2 instances should know exactly which S3 buckets to they need. The ListBuckets action is a strong indicator of compromise...or bad development practices. 
```
select useridentity.principalid,eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventsource = 's3.amazonaws.com'
and eventname = 'ListBuckets'
group by useridentity.principalid,eventsource,eventname
order by total desc
limit 25
```

## General Purpose Queries
These queries are useful for exploring potential issues and building upon for threat hunting.

### Most common API actions for a given day
```
select eventname,count(*) as total
from cloudtrail_000000000000 
where year = '####' and month = '##' and day = '##'
group by eventname
order by total desc
```
### Most common error codes
```
select errorcode, count(errorcode) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
group by errorcode
order by total desc
```

#### Principals getting denied the most
```
select useridentity.principalid, count(*) as deniedactions
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and errorcode = 'AccessDenied'
group by useridentity.principalid
order by deniedactions desc
limit 25
```

### Common denied actions from specific principal (see above)
```
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and errorcode = 'AccessDenied'
and useridentity.principalid = 'AROAxxxxxxxxxxxxxxxxx:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc
```

# API Watchlist
> these are better suited for event driven alerting, and that's what the Terraform in this repo aims to provide.

## IAM
### Root Credential Use
* Technique: T1078 Valid Accounts
* Tactic: 
  * TA0001 Initial Access
  * TA0003 Persistence
* GuardDuty:
  * Policy:IAMUser/RootCredentialUsage

All Root account events

```
select * 
from cloudtrail_000000000000
where year = '####' and month = '##' 
and useridentity.type = 'Root'
```

Only ConsoleLogin event from Root

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' 
and eventname = 'ConsoleLogin'
and useridentity.type = 'Root'
```

### Remove MFA from an IAM User
While IAM Policy may still include a condiion that requires MFA, removing MFA from an IAM User enables a pivot to that principal.

* Technique: T1531 Account Access Removal

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' 
and eventname IN ('DeactivateMFADevice', 'DeleteVirtualMFADevice')
```

### All IAM Changes
* GuardDuty
  * Persistence:IAMUser/UserPermissions

The IAM API has numerous actions for establishing persistence and expanding permissions. The following query removes read only actions. 
```
select useridentity.principalid, eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'iam.amazonaws.com'
and eventname not like 'Get%' 
and eventname not like 'List%'
and eventname not like 'Generate%'
group by useridentity.principalid, eventname
order by total desc
```

### Creation of IAM Principals
```
select useridentity.principalid, eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'iam.amazonaws.com'
and evenname in ('CreateUser','CreateRole','CreateServiceLinkedRole')
```

### Privilege Escalation: IAM Policy
IAM Policy updates used to expand permissions of associated principals (IAM Users, IAM Roles).

* RhinoSec
  * (1) Creating a new policy version
  * (2) Setting the default policy version to an existing version

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventName IN ('CreatePolicyVersion','SetDefaultPolicyVersion')
order by eventtime desc
```

### Add/Update Credentials
* RhinoSec:
  * (4) Creating a new user access key
  * (5) Creating a new login profile
  * (6) Updating an existing login profile
* Pacu:
  * ```iam__backdoor_users_keys```
  * ```iam__backdoor_users_password```

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventName IN ('CreateAccessKey', 'UpdateAccessKey',
'CreateLoginProfile','UpdateLoginProfile',
'CreateVirtualMFADevice','DeactivateMFADevice','DeleteVirtualMFADevice','EnableMFADevice'
'CreateServiceSpecificCredential','UpdateServiceSpecificCredential',
'ResetServiceSpecificSredential','DeleteServiceSpecificCredential',
'UploadServerCertificate','DeleteServerCertificate',
'UploadSigningCertificate','UpdateSigningCertificate','DeleteSigningCertificate',
'UploadSSHPublicKey','UpdateSSHPublicKey','DeleteSSHPublicKey'
)
order by eventtime desc
```

### Privilege Escalation: Adding permissions
Permission expansion may include disassociating a principal from an IAM Policy due to the removal of explicit Deny effects.
* Technique: 
  * T1098 Account Manipulation
* Tactic:
  * TA0003 Persistence
  * TA0006 Account Manipulation
* RhinoSec:
  * (7) Attaching a policy to a user
  * (8) Attaching a policy to a group
  * (9) Attaching a policy to a role
  * (10) Creating/updating an inline policy for a user
  * (11) Creating/updating an inline policy for a group
  * (12) Creating/updating an inline policy for a role
  * (13) Adding a user to a group

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventSource = 'iam.amazonaws.com' 
and eventName IN ('AttachUserPolicy', 'DetachUserPolicy',
'AttachRolePolicy', 'DetachRolePolicy',
'PutUserPolicy','PutGroupPolicy','PutRolePolicy',
'DeleteUserPolicy','DeleteGroupPolicy','DeleteRolePolicy',
'DeleteRolePermissionsBoundary')
order by eventtime desc
```

### Privilege Escalation: Expand Access to an IAM Role
* RhinoSec
  * (14) Updating the AssumeRolePolicyDocument of a role
* Pacu
  * ```iam__backdoor_assume_role```

> Updating a trust policy (`UpdateAssumerolePolicy`) allows a service, local account principal, or external account to assume the associate IAM Role and its permissions.

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventSource = 'iam.amazonaws.com' 
and eventName IN ('UpdateAssumeRolePolicy')
order by eventtime desc
```
Action | Impact
------------ | -------------
UpdateAssumeRolePolicy | Persistence / Privilege escalation allowing an IAM User to assume an IAM Role and its associated permissions

### Modify Federated Access
* Tactics
  * TA0001 Initial Access
  * TA0003 Persistence
* Techniques
  * T1098 Account Manipulation
  * T1199 Trusted Relationship

> Adding a new identity provider (`CreateSAMLProvider`)  also requires adding or updating an IAM's Role's trust policy.

> Updating the metadata (`UpdateSAMLProvider`) for a SAML IdP would hijack an existing trusted relationship, but break existing federated access.

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventName IN ('CreateSAMLProvider','UpdateSAMLProvider','DeleteSAMLProvider',
'CreateOpenIDConnectProvider','DeleteOpenIDConnectProvider','UpdateOpenIDConnectProviderThumbprint',
'AddClientIDToOpenIDConnectProvider','RemoveClientIDFromOpenIDConnectProvider')
order by eventtime desc
```

## S3
* Tactics
  * TA0005 Defense Evasion
  * TA0010 Exfiltration
  * TA0006 Credential Access
* Techniques
  * T1029 Scheduled Transfer
  * T1537 Transfer Data to Cloud Account
  * T1081 Credentials in Files
* GuardDuty
  * Stealth:S3/ServerAccessLoggingDisabled

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname in ('DeleteBucket','DeleteBucketPolicy',
'PutBucketAcl','PutBucketCORS','PutBucketPolicy','PutReplicationConfiguration',
'PutBucketLogging','PutEncryptionConfiguration','PutLifecycleConfiguration','PutObjectAcl',
'RestoreObject')
order by eventtime desc
```

> For object access logging suppression, in addition to `s3:PutBucketLogging` see also `cloudtrail:PutEventSelectors` for logging configuration of data events.

Action | Impact
------------ | -------------
DeleteBucket | Stealth, if bucket contains logs
DeleteBucketPolicy | Expand access if explicit denies are removed
PutBucketAcl | Expand access (exfil, pivot)
PutBucketCORS | Potential for data exfiltration 
PutBucketPolicy | Expand access to bucket
PutReplicationConfiguration | Expand access if target bucket is less restrictive, exfil data
PutBucketLogging | Stealth, disable logging
PutEncryptionConfiguration | Disable encryption, exfil cleartext data
PutLifecycleConfiguration | Exfil data if lifecycle rule incluces a more permissive target
PutObjectAcl | Expand access to object
RestoreObject | Access an archived object 

## EC2

### General
* Tactics
  * TA0010 Exfiltration
  * TA0003 Persistence
* Technique
  * T1108 Redundant Access

Action | Impact
------------ | -------------
GetPasswordData | Credential access
ModifyImageAttribute | Exfiltration
ModifySnapshotAttribute | Exfiltration

### EBS Encryption Account-wide Setting
* Technique
  * T1492 Stored Data Manipulation
  * T1486 Data Encrypted for Impact
* Tactic
  * TA0040 Impact

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'ec2.amazonaws.com'
and eventname IN ('EnableEbsEncryptionByDefault','DisableEbsEncryptionByDefault')
```

### Share EBS Snapshot
* Tactics
  * TA0010 Exfiltration
* Techniques
  * T1537 Transfer Data to Cloud Account


> ```--user-ids 000000000000``` is used to share with an external account

> ```--group-names all``` is used to share publicly

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'ec2.amazonaws.com'
and eventname = 'ModifySnapshotAttribute'
```

### Modify UserData
* Technique
  * T1108 Redundant Access
  * T1089 Disabling Security Tools
  * T1496 Resource Hijacking
* Tactic
  * TA0003 Persistence
  * TA0005 Defensive Evasion
* General
  * Tampering / Defacement
  * Data exfiltration
  * Secrets collection
  * Pivot from trusted access

> An EC2 instance will execute UserData with root-level permissions on start/re-start. The instance must be in a stopped state to configure the userdata update.

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname = 'ModifyInstanceAttribute'
and requestParameters like '%userData%'
```

### Network Access
* Technique
  * T1108 Redundant Access
  * T1089 Disabling Security Tools
* Tactic
  * TA0003 Persistence
  * TA0005 Defensive Evasion

Network Access Control List (NACL) configuration

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN (
   'CreateNetworkAcl',
   'CreateNetworkAclEntry',
   'DeleteNetworkAcl',
   'DeleteNetworkAclEncry'
   )
order by eventtime desc
```

Security group configuration

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN (
   'AuthorizeSecurityGroupIngress',
   'AuthorizeSecurityGroupEgress'
   'CreateSecurityGroup',
   'ModifyInstanceAttribute'
   )
order by eventtime desc
```

Action | Impact
------------ | -------------
AuthorizeSecurityGroupIngress | expand EC2 isntance inbound traffic permissions (persistance, exfil, or exploit)
AuthorizeSecurityGroupEgress | expand EC2 instance initiated outbound traffic permissions (exfil data or pivot)
CreateSecurityGroup | supports ingress/egress permissions for any associated EC2 instance
ModifyInstanceAttribute | in this context, may be used to attach a security group to an EC2 instance network interface

### Traffic Mirroring
Traffic Mirroring is a full packet capture (pcap) capability that may be used by an adversary to exfil secrets and sensitive data from unencrypted internal traffic. Within a VPC a traffic mirroring `session` is established with collection `filter` `rules` that identify what traffic to collect and forward to a `target`. 

> https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html
> https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-filters.html
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN (
    'CreateTrafficMirrorFilter',
    'CreateTrafficMirrorFilterRule',
    'CreateTrafficMirrorSession',
    'CreateTrafficMirrorTarget'
    )
```

Action | Impact
------------ | -------------
CreateTrafficMirrorFilter | expand EC2 isntance inbound traffic permissions (persistance, exfil, or exploit)
CreateTrafficMirrorFilterRule | configures the traffic to capture rules applied to a filter
CreateTrafficMirrorSession | establishes a packet capture session
CreateTrafficMirrorTarget | forwards captures traffic to an adversary controlled resource

### Network Routing

> Actions in this category have a high degree of legitimate use and are most helpful when correlated with other IoCs

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN (
    'CreateRoute',
    'CreateRouteTable',
    'DeleteRouteTable',
    'DeleteRoute',
    'DisassociateRouteTable',
    'ReplaceRoute',
    'ReplaceRouteTableAssociation' 
    )
order by eventtime desc
```

Action | Impact
------------ | -------------
CreateRoute | adds a new route (reroute/hijack traffic)
CreateRouteTable | adds a new route table (reroute/hijack traffic)
DeleteRouteTable | remove existing routing
DeleteRoute |  remove existing routing
DisassociateRouteTable | remove existing routing
ReplaceRoute | re-route existing traffic flow (hijack)
ReplaceRouteTableAssociation | re-route traffic (reroute/hijack traffic)

> The following events are less common than routing changes above, but should be correlated with other IoCs

> These events are high impact to a VPC's ingress/egress traffic flow 

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN (
    'CreateCustomerGateway',
    'DeleteCustomerGateway',
    'AttachInternetGateway',
    'CreateInternetGateway',
    'DeleteInternetGateway',
    'DetachInternetGateway'
)
order by eventtime desc
```

## Lambda
No API event in isolation should be concerning, so the importance of establishing context around Lambda service events is critical. Attackers may use existing Lambda functions to inherit elevated permissions as a pivot, for establishing persistence, or for accessing data. The actions indicated in this section are the most important to look for, but are by no means the only Lambda actions to care about in incident response.

* Technique
  * T1108 Redundant Access
  * T1089 Disabling Security Tools
  * T1496 Resource Hijacking
* Tactic
  * TA0003 Persistence
  * TA0005 Defensive Evasion
* RhinoSec
  * (15) Passing a role to a new Lambda function, then invoking it
  * (17) Updating the code of an existing Lambda function
* General
  * Tampering / Defacement
  * Data exfiltration
  * Secrets collection
  * Pivot from trusted access

Action | Impact
------------ | -------------
AddLayerVersionPermission | increase permissions for lambda:InvokeFunction (e.g. external account)
AddPermission | increase permissions for lambda:InvokeFunction (e.g. external account)
PublishLayerVersion | rogue update of function code
PublishVersion | rogue update of function code
UpdateFunctionCode | rogue update of function code

## Disruption and Evasion

### CloudTrail
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion
* GuardDuty Findings:
  * Stealth:IAMUser/CloudTrailLoggingDisabled
  * Stealth:IAMUser/LoggingConfigurationModified
* Pacu:
  * ```detection__disruption``` - `DeleteTrail` (del), `StopLogging` (dis), UpdateTrail (min)
 
#### CloudTrail Disruption
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('DeleteTrail','StopLogging','UpdateTrail',
'PutEventSelectors')
```

Action | Impact
------------ | -------------
DeleteTrail | disrupt recording
StopLogging | disrupt recording and delivery
UpdateTrail | disrupt log delivery, minify * --no-include-global-service-events * --no-is-multi-region-trail * --no-enable-log-file-validation
PutEventSelectors | disrupt data events for S3 and/or Lambda

To-do:
- [ ] bucket deletion
- [ ] bucket object deletion
- [ ] bucket tampering

### Config

#### Disrupt Config Recording, Evaluation, and Remediation
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion
* Pacu
  * ```detection__disruption``` | `DeleteConfigurationRecorder` (del), `StopConfigurationRecorder` (dis)

> CloudTrail may still log resource configuration actions
> Goals here are to prevent resource configuration history (for forensics), non-compliance detection, and remediation
> Offensive capability may be introduced through Systems Manager Automation as remediation action

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'config.amazonaws.com'
and eventname IN ('DeleteConfigRule','DeleteOrganizationConfigRule',
'DeleteConfigurationAggregator','DeleteConfigurationRecorder',
'DeleteConformancePack','DeleteOrganizationConformancePack',
'DeleteDeliveryChannel','PutDeliveryChannel',
'DeleteRemediationConfiguration','DeleteRetentionConfiguration',
'PutConfigRule', 'PutConfigurationAggregator','PutConformancePack',
'PutOrganizationConfigRule','PutOrganizationConformancePack',
'PutRemediationConfigurations','PutRemediationExceptions',
'PutRetentionConfiguration',
'StopConfigurationRecorder')
```

Action | Impact
------------ | -------------
DeleteConfigRule | Update to not detect non-compliant resources configurations
DeleteConfigurationAggregator | Update to not detect non-compliant resources configurations
DeleteConfigurationRecorder | Resource configuration changes will no longer be recorded
DeleteConformancePack | Update to not detect non-compliant resources configurations
DeleteDeliveryChannel | Remove Config service settings (s3 bucket, sns topic, delivery frequency). Requires StopConfigurationRecorder
DeleteOrganizationConfigRule | Update to not detect non-compliant resources configurations
DeleteOrganizationConformancePack | Update to not detect non-compliant resources configurations
DeleteRemediationConfiguration | Update to not auto-remediate compromised resource configuration
DeleteRetentionConfiguration | Update to not retain resource configuration history
PutConfigRule | Update to not detect non-compliant resources configurations
PutConfigurationAggregator | Update to not detect non-compliant resources configurations
PutConformancePack | Update to not detect non-compliant resources configurations
PutDeliveryChannel | Update Config service settings (s3 bucket, sns topic, delivery frequency)
PutOrganizationConfigRule | Update to not detect non-compliant resources configurations
PutOrganizationConformancePack | Update to not detect non-compliant resources configurations
PutRemediationConfigurations | Update to not remediate compromised resource configuration, update to execute arbitrary API actions
PutRemediationExceptions | Update to not remediate compromised resource configuration
PutRetentionConfiguration | Update to not retain resource configuration history
StopConfigurationRecorder | resource configuration changes will no longer be recorded

To-do:
- [ ] S3 Bucket disruption
- [ ] Disable stream configuration changes and notifications to an Amazon SNS topic
- [ ] Explain use of AWS Config role for privilege escalation

### GuardDuty
GuardDuty is AWS' managed threat detection services. The service evaluates VPC Flow Logs, CloudTrail, and Route53 query logs using signature and machine learning-backed detection methods. There are numerous methods for bypassing detection both through GuardDuty re-configuration and operating within its blind spots.

#### GuardDuty Disruption
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion
* Pacu
  * ```guardduty__whitelist_ip``` - UpdateIPSet
  * ```detection__disruption``` - DeleteDetector, UpdateDetector --no-enable

> `Disable GuardDuty` in the Web console translates to the `DeleteDetector` API call and Pacu's `Delete` option

> `Suspend GuardDuty` in the Web console translates to the `UpdateDetector --no-enable` API call and Pacu's `Disable` option

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('CreateFilter','CreateIPSet','CreateSampleFindings','CreateThreatIntelSet',
'DeleteDetector','DeleteMembers','DeletePublishingDestination','DeleteThreatIntelSet',
'DisassociateFromMasterAccount','DisassociateMembers','StopMonitoringMembers',
'UpdateDetector','UpdateFilter','UpdateIPSet','UpdatePublishingDestination','UpdateThreatIntelSet')
order by eventtime desc
```

Action | Impact
------------ | -------------
CreateFilter | Evate detection. Exempts findings (auto-archive)
CreateIPSet | Evate detection. Exempts a potentially malicious IP as trusted
CreateSampleFindings | Chaos. Flood GuardDuty with sample findings as a diversion
CreateThreatIntelSet | Chaos. Flood GuardDuty with false positives as a diversion
DeleteDetector | Evate detection
DeleteMembers | Evate detection. Master unaware of member findings. Significant impact if event handling for findings is handled only at the master.
DeletePublishingDestination | Disrupt event flow for threat findings
DeleteThreatIntelSet | Custom IP threat list not evaluated
DisassociateFromMasterAccount | Bypass detection. Master unaware of member findings
DisassociateMembers | Evate detection. Master unaware of member findings
StopMonitoringMembers | Master unaware of member findings
UpdateDetector | Evate detection. set -no-enable
UpdateFilter | see CreateFilter
UpdateIPSet | see CreateIPSet
UpdatePublishingDestination | see DeletePublishingDestination
UpdateThreatIntelSet | see DeleteThreatIntelSet

#### GuardDuty Recon
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('ListMembers','GetMembers',
'ListDetectors','GetDetector',
'ListFilters','GetFilter',
'ListIPSets','GetIPSet',
'ListThreatIntelSets','GetThreatIntelSet')
order by eventtime desc
```

### IAM Access Analyzer
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('CreateArchiveRule','DeleteAnalyzer',
'UpdateArchiveRule','UpdateFindings')
order by eventtime desc
```

> Note: `organizations.amazonaws.com` has an API action for `DeregisterDelegatedAdministrator`

Action | Impact
------------ | -------------
CreateArchiveRule | Evade detection. Auto-archive matched findings
DeleteAnalyzer | Evade detection. Suppress all findings
UpdateArchiveRule | Evade detection. Auto-archive matched findings
UpdateFindings | Evate detection. Archive sepcific findings

### Inspector

> https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoninspector.html

> https://docs.aws.amazon.com/cli/latest/reference/inspector/index.html

* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('DeleteAssessmentRun','DeleteAssessmentTarget',
'DeleteAssessmentTemplate','UnsubscribeFromEvent','UpdateAssessmentTarget')
order by eventtime desc
```

### Macie(2)
> This section applies to the new Macie ```macie2.amazonaws.com``` which is not Macie "classic"

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('ArchiveFindings','CreateFindingsFilter',
'DeleteMember','DisassociateFromMasterAccount','DisassociateMember',
'DisableMacie',
'UpdateFindingsFilter','UpdateMacieSession','UpdateMemberSession','DisableOrganizationAdminAccount',
'UpdateClassificationJob','UpdateFindingsFilter')
order by eventtime desc
```
> Note that DeregisterDelegatedAdministrator is an eventsource organizations.amazonaws.com

Action | Impact
------------ | -------------
ArchiveFindings | Bypass detection by retroactively removing findings
CreateFindingsFilter | Bypass detection by setting auto-archive rules (suppress findings)
Organizations:DeregisterDelegatedAdministrator | sever delegated admin account from organization master configuration
DeleteMember | Bypass detection. After disassociation (still enabled, not reported to master), deleting a member disabled Macie for the Member.
DisassociateFromMasterAccount | Bypass detection. Macie is still enabled on member, but findings are not reported to master
DisassociateMember | Bypass detection. Macie is still enabled on member, but findings are not reported to master
DisableMacie | Bypass detection. Disables Macie and deletes Macie resources
UpdateFindingsFilter | Bypass detection by setting auto-archive rules (suppress findings)
UpdateMacieSession | "requestParameters": {"status": "PAUSED"}, Bypass decection by suspending Macie or updating Macie configurations
UpdateMemberSession | "requestParameters": {"status": "PAUSED"}, Bypass detection by suspending Macie or updating Macie configurations
DisableOrganizationAdminAccount | Remove delegated administration account for Macie
UpdateClassificationJob | Bypass detection by removing scanned resources
UpdateFindingsFilter | Bypass detection by suppressing findings

### EC2

#### Disrupt VPC Flow Logs
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'ec2.amazonaws.com'
and eventname = 'DeleteFlowLogs'
```

> Note: GuardDuty, if enabled, monitors VPC Flow Logs independent of logging configuration. This disruptions primarily impacts custom monitoring solutions and 3rd party software.

Action | Impact
------------ | -------------
DeleteFlowLogs | Bypass detection by disabling collection of net flow

### S3
* Tactic
  * TA0009 Collection
  * TA0010 Exfiltration
* Technique
  * T1530 Data from Cloud Storage Object
  * T1029 Scheduled Transfer
  * T1537 Transfer Data to Cloud Account

#### Permissions Update

```
select eventTime, eventSource, eventName, awsRegion, errorCode, errorMessage, userIdentity.arn, sourceIPAddress, requestParameters
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 's3.amazonaws.com'
and eventname in (
    'PutAccessPointPolicy',
    'PutAccountPublicAccessBlock',
    'PutBucketAcl',
    'PutBucketCORS',
    'PutBucketPolicy',
    'PutBucketPublicAccessBlock',
    'PutObjectAcl'
)
order by eventTime desc
```

API Actions

Action | Type | Impact
------------ | ------------- | -------------
PutAccessPointPolicy | access permissions | expand permissions, data exfil
PutAccountPublicAccessBlock | access permissions |  expand permissions, data exfil
PutBucketAcl | access permissions |  expand permissions, data exfil
PutBucketCORS | access permissions |  expand permissions, data exfil
PutBucketPolicy | access permissions |  expand permissions, data exfil
PutBucketPublicAccessBlock | access permissions |  expand permissions, data exfil
PutObjectAcl | access permissions |  expand permissions, data exfil

#### Data Management

```
select eventTime, eventSource, eventName, awsRegion, errorCode, errorMessage, userIdentity.arn, sourceIPAddress, requestParameters
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 's3.amazonaws.com'
and eventname in (
    'PutBucketLogging',
    'PutBucketWebsite',
    'PutEncryptionConfiguration',
    'PutLifecycleConfiguration',
    'PutReplicationConfiguration',
    'ReplicateObject',
    'RestoreObject'
)
order by eventTime desc
```

API Actions

Action | Type | Impact
------------ | -------------| -------------
PutBucketLogging | data management | suppress logging
PutBucketWebsite | data management | potential to expose data for exfil
PutEncryptionConfiguration | data management | disable encryption
PutLifecycleConfiguration | data management | transfer objects to an accessible target resource, data exfil
PutReplicationConfiguration | data management | transfer objects to an accessible target resource, data exfil
ReplicateObject | data management | transfer objects to an accessible target resource, data exfil
RestoreObject | data management | access potentially sensitve (deleted/archived) data object, secrets access

### SecurityHub

References:
* https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awssecurityhub.html
* More info: https://aws.amazon.com/security-hub/faqs/

#### Terminology

Term | Description
------------ | ------------- 
Insight | saved findings filter
Master | designated account for security hub configuration and findings aggregation
Member | account associated with a master for findings forwarding and inheritence of configurations
Standard | collection of controls that may be enabled/disabled
Target | actions in Events

#### API Actions

Action | Type | Impact
------------ | ------------- | -------------
BatchDisableStandards | service | suppression of detection; deletes associated Config Rules
BatchUpdateFindings | finding | suppression of findings
DeleteActionTarget | service | suppression of alerting
DeleteInsight | finding | suppression of existing findings filter
DeleteMembers | service | sever master-member reporting to suppress findings alerting
DisableImportFindingsForProduct | service | suppress findings from source detection product
DisableSecurityHub | service | suppression of detection and alerting
DisassociateFromMasterAccount | service | sever master-member reporting to suppress findings alerting
DisassociateMembers | service | sever master-member reporting to suppress findings alerting
UpdateActionTarget | service | suppression of alerting
UpdateFindings | finding | suppression of existing findings
UpdateInsight | finding | see DeleteInsight
UpdateStandardsControl | service | suppression of findings detection

#### SecurityHub Service Disruption
* Technique
  * T1089 Disabling Security Tools
  * T1054 Indicator Blocking
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'securityhub.amazonaws.com'
and eventname in ('BatchDisableStandards',
'DeleteActionTarget','DeleteMembers',
'DisableImportFindingsForProduct','DisableSecurityHub',
'DisassociateFromMasterAccount','DisassociateMembers',
'UpdateActionTarget','UpdateStandardsControl')
```

#### SecurityHub Findings Disruption
* Technique
  * T1054 Indicator Blocking
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'securityhub.amazonaws.com'
and eventname in ('BatchUpdateFindings',
'DeleteInsight',
'UpdateFindings','UpdateInsight')
```

### Web Application Firewall (WAF)
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion

```
select *
from cloudtrail_000000000000
where (year = '####' and month = '##' and day = '##')
and eventname in ('DeleteFirewallManagerRuleGroups','DeleteIPSet',
'DeleteLoggingConfiguration','DeletePermissionPolicy','DeleteRegexPatternSet',
'DeleteRuleGroup','DeleteWebACL','DisassociateWebACL',
'PutLoggingConfiguration','PutPermissionPolicy',
'UpdateIPSet','UpdateRegexPatternSet','UpdateRuleGroup','UpdateWebACL')
```

Action | Impact
------------ | -------------
DeleteFirewallManagerRuleGroups | rexpand network access; if not managed by Firewall manager
DeleteIPSet | expand network access
DeleteLoggingConfiguration | disrupt logging
DeletePermissionPolicy | expand network access
DeleteRegexPatternSet | expand network access
DeleteRuleGroup | expand network access
DeleteWebACL | expand network access
DisassociateWebACL | expand network access
PutLoggingConfiguration | see DeleteLoggingConfiguration
PutPermissionPolicy | expand network access
UpdateIPSet | expand network access - allow attack network
UpdateRegexPatternSet | expand network access
UpdateRuleGroup | expand network access
UpdateWebACL | expand network access

# Network Flow Analysis
This is a proof-of-concept description. Expected changes for an enterprise implementation include:
* automated partitioning of account, region, year, month, day
* update S3 path per your environment

Pre-requisites include:
* Configuration of VPC Flow Logs with an S3 target
* Flow Log configuration for ALL traffic
* Resources operating within a VPC

Additional query capabilities are introduced by enriching Flow Logs with additional metadata.
> Reference: https://aws.amazon.com/blogs/aws/learn-from-your-vpc-flow-logs-with-additional-meta-data/

## Manual Setup
> Reference: https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html

### Add table to Athena
```
CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flow_logs_000000000000 (
  version int,
  account string,
  interfaceid string,
  sourceaddress string,
  destinationaddress string,
  sourceport int,
  destinationport int,
  protocol int,
  numpackets int,
  numbytes bigint,
  starttime int,
  endtime int,
  action string,
  logstatus string
)
PARTITIONED BY (`date` date)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ' '
LOCATION 's3://{bucket_name}/AWSLogs/000000000000/vpcflowlogs/{region}/'
TBLPROPERTIES ("skip.header.line.count"="1");
```
### Add date partition
Partitions limits the query return set for speed and cost savings.
```
ALTER TABLE vpc_flow_logs_000000000000
ADD PARTITION (`date`='yyyy-mm-dd')
location 's3://bucket_name}/AWSLogs/000000000000/vpcflowlogs/{region}/yyyy/mm/dd';
```
## Useful Queries
### General concepts
Packet count proves useful for surfacing a high volume of traffic on protocols with smaller payload.

measurement | query
------------ | -------------
packet count | sum(numpackets)
traffic volume | sum(numbytes)

### Inbound Traffic

#### Accepted packets by port
This is the traffic (packet count) allowed to reach your resource
`destinationaddress` is the private IP of your resource
```
select destinationport, sum(numpackets) as packets
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
and action = 'ACCEPT'
group by destinationport
order by packets desc
limit 10
```

#### Rejected packets by port
This is the traffic (packet count) blocked from reaching your resource.
REJECTED traffic may be due to a NACL Deny rule or lack of a security group rule.
`destinationaddress` is the private IP of your resource

```
select destinationport, sum(numpackets) as packets
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
and action = 'REJECT'
group by destinationport
order by packets desc
limit 10
```

#### Volume by sourceaddress
`destinationaddress` is the private IP of your resource

```
select sourceaddress, sum(numbytes) as volume
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
group by sourceaddress
order by volume desc
limit 10
```

#### Volume by destinationport
`destinationaddress` is the private IP of your resource
```
select destinationport, sum(numbytes) as volume
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
group by destinationport
order by volume desc
limit 10
```

#### Assess specific time range
`destinationaddress` is the private IP of your resource
`starttime` and `endtime` uses epoch
> Reference: https://www.epochconverter.com/

```
select *
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd') 
and destinationaddress = 'x.x.x.x'
and starttime > 1596225600
and endtime < 1596226200
```

### Outbound Traffic

#### Volume by desination

`sourceaddress` is the private IP of your resource
```
select destinationaddress, sum(numbytes) as volume
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and sourceaddress = 'x.x.x.x'
group by destinationaddress
order by volume desc
limit 10
```

#### Volume by port

`destinationaddress` is the private IP of your resource
```
select destinationport, sum(numbytes) as volume
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and sourceaddress = 'x.x.x.x'
group by destinationport
order by volume desc
limit 10
```

#### Assess specific time range
`source` is the private IP of your resource
`starttime` and `endtime` uses epoch
> Reference: https://www.epochconverter.com/

```
select *
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd') 
and sourceaddress = 'x.x.x.x'
and starttime > 1596225600
and endtime < 1596226200
```

#### Rejected by port
This is the traffic (packet count) allowed to reach your resource
`destinationaddress` is the private IP of your resource
```
select destinationport, sum(numpackets) as packets
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
and action = 'ACCEPT'
group by destinationport
order by packets desc
limit 10
```

#### Rejected by destination
```
select destinationaddress, sum(numpackets) as packets
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and sourceaddress = 'x.x.x.x'
and action = 'REJECT'
group by destinationaddress
order by packets desc
limit 10
```

### Example: Connectionless LDAP Reflection Attack
`destinationaddress` is your resource being used in the attack
`protocol` is 17/UDP
`destinationport` is 389/LDAP
```
select sourceaddress, sum(numpackets) as packets
from vpc_flow_logs_000000000000
WHERE date = DATE('yyyy-mm-dd')
and destinationaddress = 'x.x.x.x'
and protocol = 17
and destinationport = 389
group by sourceaddress
order by packets desc
```


# Useful CloudTrail fields

References
* https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
* https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
* https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html#error-code-and-error-message

Key | Values / Notes
------------ | -------------
useridentity.arn | arn:aws:sts::000000000000:assumed-role/AssumedRoleName/AssumedRoleSessionName
useridentity.accesskeyid | AKIA*****************
useridentity.sessioncontext.attributes.mfaauthenticated | true, false, null
useridentity.sessioncontext.sessionissuer.type | Role
useridentity.sessioncontext.sessionissuer.arn | arn:aws:iam::123456789012:role/RoleToBeAssumed
useridentity.sessioncontext.sessionissuer.username | RoleToBeAssumed
useridentity.principalid | AROAxxxxxxxxxxxxxxxxx:role-session-name (AIDAxxxxxxxxxxxxxxxxx, AROAxxxxxxxxxxxxxxxxx, saml:namequalifier and saml:sub keys)
useridentity.accountid | identifies access from external accounts 
useridentity.type | AssumedRole, AWSService, Unknown, IAMUser, AWSAccount, SAMLUser, Root
eventtime | date and time of request in UTC
eventsource | AWS service name xxx.amazonaws.com
eventname | the API action
awsregion | e.g. us-east-1
sourceipaddress | x.x.x.x or xxx.amazonaws.com
useragent | e.g. ```Botocore/1.13.43 Python/3.7.5 Linux/3.10.0-1127.13.1.el7.x86_64```
errorcode | may alternatively be in responseElements
errormessage | may alternatively be in responseElements
requestparameters | detailed parameters for the API action
responseElements | for create,update,delete actions
eventtype | AwsApiCall, AwsServiceEvent, AwsConsoleSignin
eventid | globally unique CloudTrail event ID, worth remembering for easier retrieval of valuable events

# Credit and References
* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
* https://medium.com/voogloo/which-cloud-trail-calls-are-important-for-security-teams-26003d9939ec
* https://github.com/elastic/detection-rules/tree/main/rules/aws
* https://github.com/duo-labs/cloudtrail-partitioner
* https://wellarchitectedlabs.com/security/
