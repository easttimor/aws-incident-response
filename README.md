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
where year = '2020' and month = '06' and day = '27'
and errorcode = 'AccessDenied'
and useridentity.principalid = 'AROAxxxxxxxxxxxxxxxxx:i-xxxxxxxxxxxxxxxxx'
group by eventname
order by total desc

#### Useful fields

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



