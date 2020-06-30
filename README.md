# incident-response

## Athena Queries
Start by implementing Cloudtrail Partitioner. The tables shown below are partitioned by account to include year, month, and day. This has the potential to significantly improve query speed and reduce cost.
Including year, month, and day greatly improves performance and data costs. Tweak queries as needed for the appropriate time windows.

### Access Key Exposure
We are looking for the following:
* what actions has this key been used for, historically and currently?
* has this key been used from any odd locations?
* has this key been used from any odd user agents?

#### All key usage
select eventtime, eventsource, eventname, sourceip, errorcode, useragent
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####'
and month = '##'

#### Look for user agent anomalies
select useragent, count(*) as total
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####'
and month = '##'
group by useragent
order by total desc

select eventtime, eventsource, eventname, sourceip, errorcode
from cloudtrail_000000000000
where useragent = 'seeAbove'
and year = '####'
and month = '##'

#### Look for source ip anomalies
select sourceip, count(*) as total
from cloudtrail_000000000000
where useridentity.accesskeyid = 'AKIAxxxxxxxxxxxxxxxx'
and year = '####'
and month = '##'
group by sourceip
order by total desc

select eventtime, eventsource, eventname, errorcode, useragent
from cloudtrail_000000000000
where sourceip = 'seeAbove'
and year = '####'
and month = '##'

### EC2 Instance Compromise

#### Most common API calls by an instance (instance profile / attached IAM Role)
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc
limit 25

#### and denied...
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-xxxxxxxxxxxxxxxxx'
and errorcode = 'AccessDenied'
group by eventname
order by total desc
limit 25

#### EC2 isntances getting the most denied actions
select useridentity.principalid, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and errorcode = 'AccessDenied'
group by useridentity.principalid
order by total desc
limit 25

#### Collectively, what actions are getting denied the most for EC2 instances
select eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventname <> 'AssumeRole'
and errorcode = 'AccessDenied'
group by eventsource,eventname
order by total desc
limit 25

#### Are any EC2 instances interacting with IAM?
select useridentity.principalid,eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventsource = 'iam.amazonaws.com'
group by useridentity.principalid,eventsource,eventname
order by total desc
limit 25

#### Are any EC2 instances enumarating S3?
select useridentity.principalid,eventsource,eventname,count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and useridentity.principalid like '%:i-%'
and eventsource = 's3.amazonaws.com'
and eventname = 'ListBuckets'
group by useridentity.principalid,eventsource,eventname
order by total desc
limit 25

### General Purpose

#### Most common API actions for a given day

select eventname,count(*) as total
from cloudtrail_000000000000 
where year = '####' and month = '##' and day = '##'
group by eventname
order by total desc

#### Most common error codes
select errorcode, count(errorcode) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
group by errorcode
order by total desc

#### Principals getting denied the most
select useridentity.principalid, count(*) as deniedactions
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and errorcode = 'AccessDenied'
group by useridentity.principalid
order by deniedactions desc
limit 25

#### Common denied actions from specific principal (see above)
select eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and errorcode = 'AccessDenied'
and useridentity.principalid = 'AROAxxxxxxxxxxxxxxxxx:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc

### Beginnings of dirty API call list
* these are better suited for event driven alerting - future project
#### Policy:IAMUser/RootCredentialUsage
select * 
from cloudtrail_000000000000
where year = '####' and month = '##' 
and useridentity.type = 'Root'

#### Persistence:IAMUser/UserPermissions
select useridentity.principalid, eventname, count(*) as total
from cloudtrail_000000000000
where year = '####' and month = '##' and day = '##'
and eventsource = 'iam.amazonaws.com'
and eventname not like 'Get%' 
and eventname not like 'List%'
and eventname not like 'Generate%'
group by useridentity.principalid, eventname
order by total desc

#### Stealth:IAMUser/CloudTrailLoggingDisabled

#### Stealth:IAMUser/LoggingConfigurationModified


### Useful fields

* useridentity.principalid

* useridentity.arn

* useridentity.accesskeyid

* useridentity.sessioncontext.attributes.mfaauthenticated
**true
**false
**null

* useridentity.sessioncontext.sessionissuer.type
**Role

* useridentity.sessioncontext.sessionissuer.arn
* useridentity.sessioncontext.sessionissuer.username
* useridentity.principalid **AROAxxxxxxxxxxxxxxxxx:role-session-name
* useridentity.accountid (identifies access from external accounts)
* useridentity.type
**AssumedRole
**AWSService
**Unknown
**IAMUser
**AWSAccount
**SAMLUser



