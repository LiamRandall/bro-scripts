## 		ssl_client_hello_count: 4096
## 		ssl_server_hello_count: 0
##		ssl_extension_count: 12288
##			code_13_count: 4096 --> Signature Algorithms
##				\0 ^F^A^F^B^F^C^E^A^E^B^E^C^D^A^D^B^D^C^C^A^C^B^C^C^B^A^B^B^B^C^A^A
##			code_15_count: 4096 --> heartbeat
##				^A
##			code_35_count: 4096 --> SessionTicket TLS
##		ssl_established_count: 0
##		ssl_alert_count: 4
##		ssl_session_ticket_handshake_count:  0
##		x509_certificate_count: 0
##		x509_extension_count:  0
##		x509_error_count: 0


global code_13_count = 0;
global code_15_count = 0;
global code_35_count = 0;

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
	{
	print fmt("connection: %s", c);
	print fmt("version: %s", version);
	print fmt("possible_ts: %s", possible_ts);
	print fmt("session_id: %s", session_id);
	print fmt("ciphers: %s", ciphers);
		}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	#print fmt("connection: %s", c);
	#print fmt("code: %s", code);
	print fmt("code details: %s", extensions[code])
	#print fmt("|val|: %s", |val|);
	if (code == 13)
		++code_13_count;
	if (code ==  15)
		++code_15_count;
	if (code == 35)
		++code_35_count;

	#if (code ==  13)
	#	print fmt("val: %s", val);
	#print fmt("---------------------------------------");
	}

event bro_done()
	{
	#print fmt("code_13_count: %s", code_13_count);
	#print fmt("code_15_count: %s", code_15_count);
	#print fmt ("code_35_count: %s", code_35_count);
}