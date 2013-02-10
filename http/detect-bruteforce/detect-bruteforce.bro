##! HTTP brute force attack detection in HTTP 
## This script is compatible with the Bro v2.1 Metric Framework

@load base/frameworks/notice
@load base/frameworks/metrics
@load base/protocols/http

module HTTP;

export {
	redef enum Notice::Type += {
	## Indicates that a host may be performing HTTP brute force attacks
	HTTP_BruteForce_Attacker ,
	## Indicates that a host was seen to be returning a large number of
	## HTTP 404 errors.  May indicate brute forcing
	HTTP_BruteForce_Victim,
	};

	redef enum Metrics::ID += {
	## Metrics to track HTTP Brute Force attackers.
	HTTP_BF_ATTACKER,
	## Metrics to track HTTP Brute Force victims.
	HTTP_BF_VICITM,
	};

	redef enum Tags += {
	## Indicator of a HTTP Brute Froce Attack.
	HTTP_404_ALERT,
	
	};

	## Defines the threshold that determines if client side HTTP 404 errors
	## have crossed into the abnormal boundry
	const http_orig_404_threshold = 25 &redef;

	## Defines the threshodl that determins if server side HTTP 404 errors
	## have crossed into the abnormal boundry
	const http_resp_404_threshold = 100 &redef;

	## Interval at which to watch for the 
	## :bro:id:`HTTP::http_client_404_threshold` variable to be crossed
	## At the end of each interval the counter is reset.
	const http_404_interval = 5min &redef;

	## URI's to ignore
	const http_uri_whitelist = set("/favicon.ico");

	## responder whitelist; do not track these sites
	## TODO: implement domain whitelist w/ regex
	const http_resp_whitelist = set("local.cnn.com","ads.cnn.com");

	## originator whitelists
	const http_orig_whitelist = set(192.168.0.1);
}

event bro_init() &priority=3
	{
	# Add filters to the metrics so that the metrics framework knows how to
	# determien when it looks like an actual attack and how to respond when
	# thresholds are corssed.

	Metrics::add_filter(HTTP_BF_ATTACKER, [$log=F,
										   $notice_threshold=http_orig_404_threshold,
										   $break_interval=http_404_interval,
										   $note=HTTP_BruteForce_Attacker]);
	Metrics::add_filter(HTTP_BF_VICITM, [$log=F,
										 $notice_threshold=http_resp_404_threshold,
										 $break_interval=http_404_interval,
										 $note=HTTP_BruteForce_Victim]);
	}

event http_begin_entity(c:connection, is_orig: bool)
	{
	# If something sent by the origionator bail out

	if (is_orig)
		return;;

	# Headers are not processed yet
#   if (!(c$http?$status_code) || !(c$http?$host) 
#	|| (c$http$status_code in http_status_code_whitelist) 
#	|| (c$http$host in http_resp_whitelist)) 

    if (!(c$http?$status_code) || !(c$http?$host)) 
        return;
    
    # Whitelist certain URI's; especially the favicon.ico which is commonly not setup
    if ((c$http?$uri) && (c$http$uri in http_uri_whitelist))
	   	return;

    if ((c$http?$host) && (c$http$host in http_resp_whitelist))
	   	return;

	if ((c$id?$orig_h) && (c$id$orig_h in http_orig_whitelist))
		return;

    if (c$http$status_code == 404)
    	{
    		Metrics::add_data(HTTP_BF_ATTACKER, [$host=c$id$orig_h], 1);
    		Metrics::add_data(HTTP_BF_VICITM, [$str=c$http$host], 1);
    	}
	}