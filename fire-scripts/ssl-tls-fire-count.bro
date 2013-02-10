## ssl-tls-fire-count.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## This script will provide a series of metrics about the number of times eash script fired

global ssl_client_hello_count=0;
global ssl_server_hello_count=0;
global ssl_extension_count=0;
global ssl_established_count=0;
global ssl_alert_count=0;
global ssl_session_ticket_handshake_count=0;
global x509_certificate_count=0;
global x509_extension_count=0;
global x509_error_count=0;

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
	{
	++ssl_client_hello_count;
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, session_id: string, cipher: count, comp_method: count)
	{
	++ssl_server_hello_count;
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	++ssl_extension_count;
	}

event ssl_established(c: connection)
	{
	++ssl_established_count;
	}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
	{
	++ssl_alert_count;
	}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
	{
	++ssl_session_ticket_handshake_count;
	}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	++x509_certificate_count;
	}

event x509_extension(c: connection, is_orig: bool, data: string)
	{
	++x509_extension_count;
	}

event x509_error(c: connection, is_orig: bool, err: count)
	{
	++x509_error_count;
	}


event bro_done()
    {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
	print fmt("ssl_client_hello_count: %s", ssl_client_hello_count);
	print fmt("ssl_server_hello_count: %s", ssl_server_hello_count);
	print fmt("ssl_extension_count: %s", ssl_extension_count);
	print fmt("ssl_established_count: %s", ssl_established_count);
	print fmt("ssl_alert_count: %s",ssl_alert_count);
	print fmt("ssl_session_ticket_handshake_count:  %s",ssl_session_ticket_handshake_count);
	print fmt("x509_certificate_count: %s",x509_certificate_count);
	print fmt("x509_extension_count:  %s",x509_extension_count);
	print fmt("x509_error_count: %s",x509_error_count);



    }

