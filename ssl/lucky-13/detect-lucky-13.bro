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

@load base/frameworks/notice 
@load base/frameworks/metrics
@load base/protocols/ssl

export {
	redef enum Notice::Type += {
	## Indicates that a host may be performing TLS attack
	TLS_Attacker,
	## Indicates that a host may be under TLS attack
	TLS_Victim,
	};

	redef enum Metrics::ID += {
	## Metrics to track 
	TLS_ATTACKER_CLIENT_HELLO,
	TLS_VICTIM_CLIENT_HELLO,
	};
	# how many hello's are too many
	const tls_attacker_client_hello_threshold = 50 &redef;
	const tls_victim_client_hello_threshold =50 &redef;

	# over what period do we watch for the number of hello's to be exceeded
	const tls_attacker_client_hello_interval = 1min &redef;
	const tls_victim_client_hello_interval = 1 min &redef;

	# white list these hosts
	# if you use this whitelist, please email me a pcap!
	const tls_attacker_whitelist = set(192.168.0.1);
	const tls_victim_whitelist = set(192.168.0.1);
}

event bro_init() &priority=3
	{
	# Add filters to the metrics framework to track & respond when crossed

	Metrics::add_filter(TLS_ATTACKER_CLIENT_HELLO, [$log=F,
													 $notice_threshold=tls_attacker_client_hello_threshold,
													 $break_interval=tls_attacker_client_hello_interval,
													 $note=TLS_Attacker]);


	Metrics::add_filter(TLS_VICTIM_CLIENT_HELLO, [$log=F,
								 				  $notice_threshold=tls_victim_client_hello_threshold,
												  $break_interval=tls_victim_client_hello_interval,
												  $note=TLS_Victim]);
}

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
	{
	# do not track hosts in either of the whitelists
	if ((c$id?$orig_h) && (c$id$orig_h in tls_attacker_whitelist))
		return;

	if ((c$id?$resp_h) && (c$id$resp_h in tls_victim_whitelist))
		return;
	# let's track the count off the item over time
	Metrics::add_data(TLS_ATTACKER_CLIENT_HELLO, [$host=c$id$orig_h], 1);
	Metrics::add_data(TLS_VICTIM_CLIENT_HELLO, [$host=c$id$resp_h], 1);

	}
