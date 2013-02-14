## ssl-tls-fire-count.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## This script will provide a series of metrics about the number of times eash script fired

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
	{
	print fmt("event ssl_client_hello");
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, session_id: string, cipher: count, comp_method: count)
	{
	print fmt("event ssl_server_hello");
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	print fmt("event ssl_extension");
	}

event ssl_established(c: connection)
	{
	print fmt("event ssl_established");
	}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
	{
	print fmt("event ssl_alert");
	}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
	{
	print fmt("event ssl_session_ticket_handshake");
	}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	print fmt("event x509_certificate");
	}

event x509_extension(c: connection, is_orig: bool, data: string)
	{
	print fmt("event x509_extension");
	}

event x509_error(c: connection, is_orig: bool, err: count)
	{
	print fmt("event x509_error");
	}


event bro_done()
        {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
        }

