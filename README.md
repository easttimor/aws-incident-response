# CloudTrail Queries using Athena

This page is a collection of useful things to look for in CloudTrail. Filters may be created to alert to these actions. The queries may also prove useful for threat hunting and incidend response.

While these same concepts/capabilities may be implemented outside of Athena, this page's examples are SQL and leverage Athena tables and partitions.

Start by implementing Cloudtrail Partitioner. The SQL "tables" shown below are partitioned by account to include year, month, and day. Partitions act like an index, enabling Athena to query smaller data sets. This query efficiency has the potential to significantly improve query speed and reduce cost.
Including year, month, and day greatly improves performance and data costs. Tweak queries as needed for the appropriate time windows.

To-do:
- [ ] more service coverage (particularly network and storage)
- [ ] consistent mapping to ATT&CK
- [ ] Event filter library (in this repo), automated detection and alerting

## Access Key Exposure
We are looking for the following:
* what actions has this key been used for, historically and currently?
* has this key been used from any odd locations?
* has this key been used from any odd user agents?

### All key usage
```
select eventtime, eventsource, eventname, sourceip, errorcode, useragent
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####' and month = '##'
```
### Look for user agent anomalies
```
select useragent, count(*) as total
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####' and month = '##'
group by useragent
order by total desc
```
```
select eventtime, eventsource, eventname, sourceip, errorcode
from cloudtrail_000000000000
where useragent = 'seeAbove'
and year = '####' and month = '##'
```
### Look for source ip anomalies
```
select sourceip, count(*) as total
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####' and month = '##'
group by sourceip
order by total desc
```
```
select eventtime, eventsource, eventname, errorcode, useragent
from cloudtrail_000000000000
where sourceip = 'seeAbove'
and year = '####'
and month = '##'
```
## EC2 Instance Compromise
EC2 instances may have an IAM Role attached to them. The combination of the instance and the role is called an "instance profile". When the role is assumed, the EC2 instance ID is used as the session name part of the Principal ARN in CloudTrail. We can identify actions of EC2 instances using the clause ```useridentity.principalid like '%:i-%'``` or a specific EC2 instance ```useridentity.principalid like '%:i-00000000000000000'```

The actions of EC2 instances will typically be repetitive and persistent, because all actions are presumed to be initiated by software and not a human. Play close attention to any anomalous API calls. An attacker with access to an EC2 instance has access to any IAM permissions granted to that instance via the instance profile.

### Recent API calls with a specific instanceId as the target resource
> Very inefficient I know - room for improvement here

> The CloudTrail UI provides `resource name` as search criteria. Note that `resource name` is not an actual key in the JSON so they're abstracting some query magic. Relevant events may not be included in this CloudTrail API query - otherwise stated, the below Athena query will show you more events for better or worse.

```
select eventTime, eventName, eventSource
from cloudtrail_000000000000
where year = 'xxxx' and month = 'xx' and day = 'xx'
and (requestParameters like '%i-xxxxxxxxxxxxxxxxx%' or responseElements like '%i-xxxxxxxxxxxxxxxxx%')
and eventname not like 'Describe%'
and eventsource = 'ec2.amazonaws.com'
limit 25
```

### Most common API calls by an instance (instance profile / attached IAM Role)
```
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc
limit 25
```
### ...that were denied
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
### EC2 instances getting the most denied actions
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
### Collectively, what actions are getting denied the most for EC2 instances
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
### Are any EC2 instances interacting with IAM?
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
### Are any EC2 instances enumarating S3?
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
## General Purpose

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
> these are better suited for event driven alerting - future project

## IAM
### Root Credential Use
* Technique: T1078 Valid Accounts
* Tactic: 
  * TA0001 Initial Access
  * TA0003 Persistence
* GuardDuty:
  * Policy:IAMUser/RootCredentialUsage
```
select * 
from cloudtrail_000000000000
where year = '####' and month = '##' 
and useridentity.type = 'Root'
```

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
* GuardDuty:
  * Persistence:IAMUser/UserPermissions
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
### Privilege Escalation: IAM Policy
IAM Policy updates used to expand permissions of associated principals (IAM Users, IAM Roles).

* RhinoSec:
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
and eventName IN ('CreateAccessKey', 
'CreateLoginProfile','UpdateLoginProfile',
'CreateVirtualMFADevice','DeactivateMFADevice','DeleteVirtualMFADevice','EnableMFADevice'
'CreateServiceSpecificCredential','UpdateServiceSpecificCredential','DeleteServiceSpecificCredential',
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
* RhinoSec:
  * (14) Updating the AssumeRolePolicyDocument of a role
* Pacu:
  * ```iam__backdoor_assume_role```
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

### Enable/Disable EBS Encryption
* Technique
  * T1492 Stored Data Manipulation
  * T1486 Data Encrypted for Impact
* Tactic
  * TA0040 Impact

#### Account-wide Setting
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

## Network Access
* Technique
  * T1108 Redundant Access
  * T1089 Disabling Security Tools
* Tactic
  * TA0003 Persistence
  * TA0005 Defensive Evasion
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('CreateNetworkAcl','CreateNetworkAclEntry',
'DeleteNetworkAcl','DeleteNetworkAclEncry')
order by eventtime desc
```

```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname IN ('AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress'
'CreateSecurityGroup','ModifyInstanceAttribute')
order by eventtime desc
```
Action | Impact
------------ | -------------
AuthorizeSecurityGroupIngress | expand EC2 isntance inbound traffic permissions (persistance, exfil, or exploit)
AuthorizeSecurityGroupEgress | expand EC2 instance initiated outbound traffic permissions (exfil data or pivot)
CreateSecurityGroup | supports ingress/egress permissions for any associated EC2 instance
ModifyInstanceAttribute | in this context, may be used to attach a security group to an EC2 instance network interface

## Modify UserData
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

An EC2 instance will execute UserData with root-level permissions on start/re-start. The instance must be in a stopped state to configure the userdata update.
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventname = 'ModifyInstanceAttribute'
and requestParameters like '%userData%'
```

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
  * ```detection__disruption``` | `DeleteTrail` (del), `StopLogging` (dis), UpdateTrail (min)
 
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
  * ```guardduty__whitelist_ip``` | UpdateIPSet
  * ```detection__disruption``` | DeleteDetector, UpdateDetector --no-enable

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

## Useful CloudTrail fields
> https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

> https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html

> https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html#error-code-and-error-message

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


## Credit and References
* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
* https://medium.com/voogloo/which-cloud-trail-calls-are-important-for-security-teams-26003d9939ec
* https://github.com/elastic/detection-rules/tree/main/rules/aws


