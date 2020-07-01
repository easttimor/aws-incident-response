# CloudTrail Queries using Athena

Start by implementing Cloudtrail Partitioner. The SQL "tables" shown below are partitioned by account to include year, month, and day. Partitions act like an index, enabling Athena to query smaller data sets. This query efficiency has the potential to significantly improve query speed and reduce cost.
Including year, month, and day greatly improves performance and data costs. Tweak queries as needed for the appropriate time windows.

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

## Beginnings of dirty API call list
* these are better suited for event driven alerting - future project

### Policy:IAMUser/RootCredentialUsage
* Technique: T1078 Valid Accounts
* Tactic: 
  * TA0001 Initial Access
  * TA0003 Persistence
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

### Persistence:IAMUser/UserPermissions
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

### Privilege Escalation: Adding permissions
Permission expansion may include disassociating a principal from an IAM Policy due to the removal of explicit Deny effects.
* Technique: 
  * T1098 Account Manipulation
* Tactic:
  * TA0003 Persistence
  * TA0006 Account Manipulation
* RhinoSec:
  * 7. Attaching a policy to a user
  * 8. Attaching a policy to a group
  * 9. Attaching a policy to a role
  * 10. Creating/updating an inline policy for a user
  * 11. Creating/updating an inline policy for a group
  * 12. Creating/updating an inline policy for a role
  * 13. Adding a user to a group
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
orderby eventtime desc
```
#### Privilege Escalation: Expand Access to an IAM Role
* RhinoSec:
  * 14. Updating the AssumeRolePolicyDocument of a role
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventSource = 'iam.amazonaws.com' 
and eventName IN ('UpdateAssumeRolePolicy')
orderby eventtime desc
```
#### Add/Update Credentials
* RhinoSec:
  * 4. Creating a new user access key
  * 5. Creating a new login profile
  * 6. Updating an existing login profile
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
#### Modify Federated Access
```
select *
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventName IN ('CreateSAMLProvider','UpdateSAMLProvider','DeleteSAMLProvider',
'CreateOpenIDConnectProvider','DeleteOpenIDConnectProvider','UpdateOpenIDConnectProviderThumbprint',
'AddClientIDToOpenIDConnectProvider','RemoveClientIDFromOpenIDConnectProvider')
order by eventtime desc
```

#### Network Access
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
and eventname IN ('AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress')
order by eventtime desc
```

## Disruption
* Technique
  * T1089 Disabling Security Tools
* Tactic
  * TA0005 Defensive Evasion
### CloudTrail
* GuardDuty Findings:
  * Stealth:IAMUser/CloudTrailLoggingDisabled

### GuardDuty

#### GuardDuty Disruption
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
CreateFilter | Bypass detection. Exempts findings (auto-archive)
CreateIPSet | Bypass detection. Exempts a potentially malicious IP as trusted
CreateSampleFindings | Chaos. Flood GuardDuty with sample findings as a diversion
CreateThreatIntelSet | Chaos. Flood GuardDuty with false positives as a diversion
DeleteDetector | Bypass detection
DeleteMembers | Bypass detection. Master unaware of member findings. Significant impact if event handling for findings is handled only at the master.
DeletePublishingDestination | Disrupt event flow for threat findings
DeleteThreatIntelSet | Custom IP threat list not evaluated
DisassociateFromMasterAccount | Bypass detection. Master unaware of member findings
DisassociateMembers | Bypass detection. Master unaware of member findings
StopMonitoringMembers | Master unaware of member findings
UpdateDetector | Bypass detection. set -no-enable
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
### Stealth:IAMUser/LoggingConfigurationModified

## Useful fields

Key | Values / Notes
------------ | -------------
useridentity.arn | 
useridentity.principalid |
useridentity.accesskeyid | AKIA*****************
useridentity.sessioncontext.attributes.mfaauthenticated | true, false, null
useridentity.sessioncontext.sessionissuer.type | Role
useridentity.sessioncontext.sessionissuer.arn | 
useridentity.sessioncontext.sessionissuer.username | 
useridentity.principalid | AROAxxxxxxxxxxxxxxxxx:role-session-name
useridentity.accountid | identifies access from external accounts 
useridentity.type | AssumedRole, AWSService, Unknown, IAMUser, AWSAccount, SAMLUser
