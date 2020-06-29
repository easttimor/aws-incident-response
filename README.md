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
