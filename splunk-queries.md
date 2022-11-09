Rex Command (Extract fields)
-----------

index=main sourcetype=secure-2
| rex "from (?<IP_ADDRESS>\d{1, 3}.\d{1,3}.\d{1,3}.\d{1,3})"

index=main sourcetype=secure-2
| rex "from (?<IP_ADDRESS>\d{1, 3}.\d{1,3}.\d{1,3}.\d{1,3})"
| search IP_ADDRESS = *
| iplocation IP_ADDRESS
| timechart count by Country



Stats Command (run aggregation)
-------------
index=main sourcetype=access_combines_wcookie
status != 200
| stats count by status


index=main sourcetype=access_combines_wcookie
| stats max(bytes) AS "BiggestRequest", min(bytes) AS "Smallest Request", median(bytes) AS "Median Request", count AS "Total Request"


index=main sourcetype=access_combines_wcookie
| stats count(eval(status = 500)) AS "Internal Server Errors"


index=main sourcetype=access_combines_wcookie
| fieldsummary maxvals=5


index=main sourcetype=access_combines_wcookie
| timechart span=1h avg(bytes) AS "Response Size"
| eventstats avg(Response Size)


index=_internal log_level=WARN OR log_level=ERROR
| stats count by component
| sort count
| streamstats sum(count)


index=main sourcetype=access_combines_wcookie action=purchase
| stats count AS "total_purchase" BY itemId
| sort 5 - total_purchase
| streamstats count AS rank



Eval command (programming like ability)
------------
index=main sourcetype=access_combines_wcookie
| eval Kbytes = bytes / 1024


index=main sourcetype=access_combines_wcookie
| eval Kbytes = bytes / 1024
| stats max(Kbytes) AS BiggestRequest by itemId
| eval BiggestRequest = ceiling(BiggestRequest)


index=main sourcetype=access_combines_wcookie
| eval result = if(like(_raw, "%Failed Password%"), "failed", "success")


index=main sourcetype=access_combines_wcookie
| eval CATEGORY = case(status >= 500, "Internal Server Error", status >= 400, "Bad Request", status == 200, "OK", 1==1, "NA")


index=main sourcetype=access_combines_wcookie
| eval itemProduct = itemId . "/" . productId



timechart (plots)
----------

index=main sourcetype=access_combines_wcookie 
| chart count BY action, status


index=main sourcetype=access_combines_wcookie  "Failed Password"
| timechart count



