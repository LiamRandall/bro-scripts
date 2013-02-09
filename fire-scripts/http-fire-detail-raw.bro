## http-fire-detail-raw.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## Upon firing of each event for the http protocol print the raw variable values to screen
##
## TODO:
## 		Test for each variable, print it, if not set not that


event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	print fmt("---------------------------------------------------------------");

	print fmt("event http_header");
#	print fmt("connection: %s", c);
	print fmt("     connection: %s", c);
	}

event http_request(c:connection, method:string, original_URI: string, unescaped_URI: string, version: string)
        {
	print fmt("---------------------------------------------------------------");
	print fmt("event http_request");
	print fmt("     connection: %s", c);
#	print fmt("");
	}
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_reply");
	print fmt("     connection: %s", c);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_header");
	print fmt("     connection: %s", c);

	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_all_headers");
	print fmt("     connection: %s", c);
	}

event http_begin_entity(c: connection, is_orig: bool)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_begin_entity");
	print fmt("     connection: %s", c);

	}

event http_end_entity(c: connection, is_orig: bool)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_end_entity");
	print fmt("     connection: %s", c);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_entity_data");
	print fmt("     connection: %s", c);
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) 
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_content_type");
	print fmt("     connection: %s", c);

	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) 
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_message_done");
	print fmt("     connection: %s", c);
	}

event http_event(c: connection, event_type: string, detail: string)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_event");
	print fmt("     connection: %s", c);
	}

event http_stats(c: connection, stats: http_stats_rec)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_stats");
	print fmt("     connection: %s", c);
	}

event http_signature_found(c: connection)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_signature_found");
	print fmt("     connection: %s", c);
	}

event http_proxy_signature_found(c: connection)
	{
	print fmt("---------------------------------------------------------------");
	print fmt("event http_proxy_signature_found");
	print fmt("     connection: %s", c);
	}


	
event bro_done()
        {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
        }
