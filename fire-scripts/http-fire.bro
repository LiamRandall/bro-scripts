## http-fire.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## Upon firing of each event for the http protocol simply print a line.



event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	print fmt("event http_header");
	}

event http_request(c:connection, method:string, original_URI: string, unescaped_URI: string, version: string)
        {
	print fmt("event http_request");
	}
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	print fmt("event http_reply");
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	print fmt("event http_header");

	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	print fmt("event http_all_headers");
	}

event http_begin_entity(c: connection, is_orig: bool)
	{
	print fmt("event http_begin_entity");

	}

event http_end_entity(c: connection, is_orig: bool)
	{
	print fmt("event http_end_entity");
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	print fmt("event http_entity_data");
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) 
	{
	print fmt("event http_content_type");

	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) 
	{
	print fmt("event http_message_done");
	}

event http_event(c: connection, event_type: string, detail: string)
	{
	print fmt("event http_event");
	}

event http_stats(c: connection, stats: http_stats_rec)
	{
	print fmt("event http_stats");
	}

event http_signature_found(c: connection)
	{
	print fmt("event http_signature_found");
	}

event http_proxy_signature_found(c: connection)
	{
	print fmt("event http_proxy_signature_found");
	}


	
event bro_done()
        {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
        }

