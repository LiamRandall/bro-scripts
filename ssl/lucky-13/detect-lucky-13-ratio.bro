##! "Lucky 13" TLS / DTLS Timing Attack Detector
## This script is compatible with the Bro v2.1 Metric Framework
##
## Attack details:
##		http://www.isg.rhul.ac.uk/tls/#Moreinfo
##		http://www.isg.rhul.ac.uk/tls/TLStiming.pdf
##
## Attack Details:
##
## Lucky 13 is a timing attack.
##
## Worse case 2^23 TLS sessions (8,388,608) HMAC-SHA1 for TLS's MAC algorith
## Reduced to 2^19 TLS sessions (524,288) if plaintext is base 64 encoded
##		Reduced possibilites by assuming natural language; app-layer (http,xml)
##		Select canidates based on 
## Best case 2^13 TLS sessions (8,192) per byte when BEAST assisted
##
## fire-script/ssl-tls-event-count.bro output 
##		https://github.com/LiamRandall/bro-scripts/tree/master/fire-scripts	
##		
## 		ssl_client_hello_count: 4096
## 		ssl_server_hello_count: 0
##		ssl_extension_count: 12288
##		ssl_established_count: 0
##		ssl_alert_count: 4
##		ssl_session_ticket_handshake_count:  0
##		x509_certificate_count: 0
##		x509_extension_count:  0
##		x509_error_count: 0
##
##	In this version of the detector we are just going to enable a detection profile for
##  on the ratio of ssl_client_hello to ssl_established_count
##  at that point we will watch for the unusual TCP tear downs

@load base/frameworks/notice 
@load base/frameworks/metrics
@load base/protocols/ssl

export {
	redef enum Notice::Type += {
	## Indicates SSL/TLS Protocol Anomolies
	TLS_Anomoly_Orig,
	## Indicateds SSL/TLS Protocol Anomolies
	TLS_Anomoly_Resp,
	## Indicates that a host may be performing TLS attack
	TLS_Lucky13_Attacker,
	## Indicates that a host may be under TLS attack
	TLS_Lucky13_Victim,
	};

	redef enum Metrics::ID += {
	## Metrics to track 
	TLS_ANOMOLY_ORIG_HELLO,
	TLS_ANOMOLY_RESP_HELLO,
	TLS_LUCKY13_ORIG,
	TLS_LUCKY13_RESP
	};

	###
	###  TLS Anomoly Detection 
	###
	# how many hello's are too many
	const tls_anomoly_orig_client_hello_threshold = 10 &redef;
	const tls_anomoly_resp_client_hello_threshold = 10 &redef;
	# over what period do we watch for the number of hello's to be exceeded
	const tls_anomoly_orig_client_hello_interval = 1min &redef;
	const tls_anomoly_resp_client_hello_interval = 1min &redef;

	###
	###	 Lucky 13 Detector
	###
	# Enable Lucky 13 detector
	global tls_enable_lucky13_detector: bool = F &redef;
	# Lucky 13 has a pretty suspicious TCP Reset; how many to trip on
	const tls_lucky13_conn_threshold = 5 &redef;
	const tls_lucky13_conn_interval = 1min &redef;

	# white list these hosts
	# if you use this whitelist, please email me a pcap!
	const tls_anomoly_orig_whitelist = set(192.168.0.1);
	const tls_anomoly_resp_whitelist = set(192.168.0.1);
	const tls_lucky13_orig_whitelist = set(192.168.0.1);
	const tls_lucky13_resp_whitelist = set(192.168.0.1);
}

event bro_init() &priority=3
	{
	# Add filters to the metrics framework to track & respond when crossed

	Metrics::add_filter(TLS_ANOMOLY_ORIG_HELLO, [$log=F,
												 $notice_threshold=tls_anomoly_orig_client_hello_threshold,
												 $break_interval=tls_anomoly_orig_client_hello_interval,
												 $note=TLS_Anomoly_Orig]);

	Metrics::add_filter(TLS_ANOMOLY_RESP_HELLO, [$log=F,
												 $notice_threshold=tls_anomoly_resp_client_hello_threshold,
												 $break_interval=tls_anomoly_resp_client_hello_interval,
												 $note=TLS_Anomoly_Resp]);

	Metrics::add_filter(TLS_LUCKY13_ORIG, [$log=F,
										   $notice_threshold=tls_lucky13_conn_threshold,
										   $break_interval=tls_lucky13_conn_interval,
										   $note=TLS_Lucky13_Attacker]);

	Metrics::add_filter(TLS_LUCKY13_RESP, [$log=F,
										   $notice_threshold=tls_lucky13_conn_threshold,
										   $break_interval=tls_lucky13_conn_interval,
										   $note=TLS_Lucky13_Victim]);

}

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
	{
	# do not track hosts in either of the whitelists
	if ((c$id?$orig_h) && (c$id$orig_h in tls_anomoly_orig_whitelist))
		return;

	if ((c$id?$resp_h) && (c$id$resp_h in tls_anomoly_resp_whitelist))
		return;
	# let's track the count off the item over time
	Metrics::add_data(TLS_ANOMOLY_ORIG_HELLO, [$host=c$id$orig_h], 1);
	Metrics::add_data(TLS_ANOMOLY_RESP_HELLO, [$host=c$id$resp_h], 1);
	}


event ssl_established(c: connection)
	{
	if ((c$id?$orig_h) && (c$id$orig_h in tls_anomoly_orig_whitelist))
		return;

	if ((c$id?$resp_h) && (c$id$resp_h in tls_anomoly_resp_whitelist))
		return;
	# let's track the count off the item over time
	Metrics::add_data(TLS_ANOMOLY_ORIG_HELLO, [$host=c$id$orig_h], -1);
	Metrics::add_data(TLS_ANOMOLY_RESP_HELLO, [$host=c$id$resp_h], -1);
	}
