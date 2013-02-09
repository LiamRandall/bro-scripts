# whitelist hosts
# client warning threshold by error, by types?

# too many 200's could be server scan
# too many 404's is bad server or bad client host

const responder_threshold_404 = 30;
const responder_threshold_500 = 30;
const http_guessing_timeout = 30 mins &redef;

# const http_ignore_guessers: table[subnet] of subnet &redef; 
# 	WTF DOES THAT EVEN MEAN??
# TODO: ALLOW WHITELIST OF SUBNETS

type RespCodeCounter: table[count] of count &default=0;
type RespHostCodeCount: table[string] of RespCodeCounter;

global http_resp_tracker: RespHostCodeCount;

type OrigRespHostCodeCount: table[addr] of RespHostCodeCount;
global http_orig_tracker: OrigRespHostCodeCount;

# responders (servers) we do not wish to track
global http_resp_whitelist = set("local.cnn.com","ads.cnn.com");
# TODO: USE INPUT FRAMEWORK TO IMPORT THIS LIST
global http_orig_whitelist : set[addr];


# status codes we do not wish to track
# http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
# 100 Continue
# 200 OK
global http_status_code_whitelist = set(100,200);


event http_begin_entity(c: connection, is_orig: bool)
 {
	# originators can also trigger this event.. check the http protocol, 
	# however we are only interested in the responders (servers) response

	if (is_orig) 
		return;;

	# Headers are not processed yet
        if (!(c$http?$status_code) || !(c$http?$host) || (c$http$status_code in http_status_code_whitelist) || (c$http$host in http_resp_whitelist)) 
                return;

	# Are we tracking this responder (server) yet? Host is not in there yet
	if (c$http$host !in http_resp_tracker)
		http_resp_tracker[c$http$host]= table();

	# Ok, this responder is in there, are we tracking this status code yet?
	if (c$http$status_code !in http_resp_tracker[c$http$host])
		http_resp_tracker[c$http$host][c$http$status_code] = 0;

	# ok the host is in there & the status, incriment the counter
	if (c$http$status_code in http_resp_tracker[c$http$host])
	{
		++http_resp_tracker[c$http$host][c$http$status_code];

		# Now we need to check our thresholds
		if ((c$http$status_code == 404) && (http_resp_tracker[c$http$host][c$http$status_code] == responder_threshold_404))
			print fmt("Server %s has experienced a high number of 404 errors, potential http brute forcing or server misconfiguration.", c$http$host);
		if ((c$http$status_code == 500) && (http_resp_tracker[c$http$host][c$http$status_code] == responder_threshold_500))
			print fmt("Server %s has experienced a hih number of \"500 Internal Server Errors\", potential DOS or server misconfiguration.", c$http$host);

	}
	# print all the things
	#	print fmt("http_resp_tracker length: %s :host: %s : status_code : %s : count : %s", |http_resp_tracker|, c$http$host, c$http$status_code, http_resp_tracker[c$http$host][c$http$status_code]);
}

event http_begin_entity(c: connection, is_orig: bool)
 {
	# Ok, lets do it again but for the clients

	if (is_orig) 
		return;;

	# Headers are not processed yet
        if (!(c$http?$status_code) || !(c$http?$host) || (c$http$status_code in http_status_code_whitelist) || (c$http$host in http_resp_whitelist) || (c$id$orig_h in http_orig_whitelist))  #orig_ip address!
                return;
	# Are we tracking this originator yet?
	if (c$id$orig_h !in http_orig_tracker)
		http_orig_tracker[c$id$orig_h]= table();

	# Are we tracking this responder (server) yet? Host is not in there yet
	if (c$http$host !in http_orig_tracker[c$id$orig_h])
	{
		http_orig_tracker[c$id$orig_h][c$http$host]= table();
		print fmt("Added http_orig_tracker[%s][%s]",c$id$orig_h,c$http$host);
	}

	# Ok, this responder is in there, are we tracking this status code yet?
	if (c$http$status_code !in http_orig_tracker[c$id$orig_h][c$http$host])
		http_orig_tracker[c$id$orig_h][c$http$host][c$http$status_code] = 0;

	# ok the host is in there & the status, incriment the counter
	if (c$http$status_code in http_orig_tracker[c$id$orig_h][c$http$host])
	{
		++http_orig_tracker[c$id$orig_h][c$http$host][c$http$status_code];

		# Now we need to check our thresholds
		if ((c$http$status_code == 404) && (http_orig_tracker[c$id$orig_h][c$http$host][c$http$status_code] == responder_threshold_404))
			print fmt("Client %s accessing server %s has experienced a high number of 404 errors, potential http brute forcing or server misconfiguration.", c$id$orig_h, c$http$host);
		if ((c$http$status_code == 500) && (http_orig_tracker[c$id$orig_h][c$http$host][c$http$status_code] == responder_threshold_500))
			print fmt("Client %s accessing server %s has experienced a hih number of \"500 Internal Server Errors\", potential DOS or server misconfiguration.", c$id$orig_h, c$http$host);

	}
	# print all the things
	#	print fmt("http_resp_tracker length: %s :host: %s : status_code : %s : count : %s", |http_resp_tracker|, c$http$host, c$http$status_code, http_resp_tracker[c$http$host][c$http$status_code]);
}

event bro_done()
	{
	# it's the final count-down </kazoo>
	for (r in http_resp_tracker)
		{
		print fmt("resp: %s", r);
		for (c in http_resp_tracker[r])
			{
			print fmt("  %s --> %s", c, http_resp_tracker[r][c]);
			}	
		}
	for (o in http_orig_tracker)
		{
		print fmt("orig: %s", o);
		for (r in http_orig_tracker[o])
			{
			print fmt("'-->resp: %s", r);
			for (c in http_orig_tracker[o][r])
				{
				print fmt("  '-->%s--> %s",c,http_orig_tracker[o][r][c]);
				}
			}
		}

	}

