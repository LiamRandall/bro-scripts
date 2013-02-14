## http-fire.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## Upon firing of each event for the http protocol simply print a line.

global http_header_count=0;
global http_request_count=0;
global http_reply_count=0;
global http_all_headers_count=0;
global http_begin_entity_count=0;
global http_end_entity_count=0;
global http_entity_data_count=0;
global http_content_type_count=0;
global http_message_done_count=0;
global http_event_count=0;
global http_stats_count=0;
global http_signature_found_count=0;
global http_proxy_signature_found_count=0;


event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	++http_header_count;
	}

event http_request(c:connection, method:string, original_URI: string, unescaped_URI: string, version: string)
    {
	++http_request_count;
	}
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	++http_reply_count;
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	++http_all_headers_count;
	}

event http_begin_entity(c: connection, is_orig: bool)
	{
	++http_begin_entity_count;
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	++http_end_entity_count;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	++http_entity_data_count;
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) 
	{
	++http_content_type_count;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) 
	{
	++http_message_done_count;
	}

event http_event(c: connection, event_type: string, detail: string)
	{
	++http_event_count;
	}

event http_stats(c: connection, stats: http_stats_rec)
	{
	++http_stats_count;
	}

event http_signature_found(c: connection)
	{
	++http_signature_found_count;
	}

event http_proxy_signature_found(c: connection)
	{
	++http_proxy_signature_found_count;
	}


	
event bro_done()
        {
		print fmt("---------------------------------------------------------------");
		print fmt("Bro is done");
		print fmt("http_header_count: %s", http_header_count);
		print fmt("http_request_count: %s", http_request_count);
		print fmt("http_reply_count: %s", http_reply_count);
		print fmt("http_all_headers_count: %s", http_all_headers_count);
		print fmt("http_begin_entity_count: %s", http_begin_entity_count);
		print fmt("http_end_entity_count: %s", http_end_entity_count);
		print fmt("http_entity_data_count: %s", http_entity_data_count);
		print fmt("http_content_type_count: %s", http_content_type_count);
		print fmt("http_message_done_count: %s", http_message_done_count);
		print fmt("http_event_count: %s", http_event_count);
		print fmt("http_stats_count: %s", http_stats_count);
		print fmt("http_signature_found_count: %s", http_signature_found_count);
		print fmt("http_proxy_signature_found: %s", http_proxy_signature_found_count);

        }

