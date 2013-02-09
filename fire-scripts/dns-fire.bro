## dns-fire.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## Upon firing of each event for the dns protocol simply print a line.

event dns_mapping_valid(dm: dns_mapping)
	{
	print fmt("event dns_mapping_valid");
	}

event dns_mapping_unverified(dm: dns_mapping)
	{
	print fmt("event dns_mapping_unverified");
	}

event dns_mapping_new_name(dm: dns_mapping)
	{
	print fmt("event dns_mapping_new_name");
	}

event dns_mapping_lost_name(dm: dns_mapping)
	{
	print fmt("event dns_mapping_lost_name");
	}

event dns_mapping_altered(dm: dns_mapping, old_addrs: addr_set, new_addrs: addr_set)
	{
	print fmt("event dns_mapping_altered");
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	print fmt("event dns_message");
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	print fmt("event dns_request");
	}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	print fmt("event dns_rejected");
	}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	print fmt("event dns_query_reply");
	}

event non_dns_request(c: connection, msg: string)
	{
	print fmt("event non_dns_request");
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print fmt("event dns_A_reply");
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print fmt("event dns_AAAA_reply");
	}

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print fmt("event dns_A6_reply");
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print fmt("event dns_NS_reply");
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print fmt("event dns_CNAME_reply");
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print fmt("event dns_PTR_reply");
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	print fmt("event dns_SOA_reply");
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	print fmt("event dns_WKS_reply");
	}

event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	print fmt("event dns_HINFO_reply");
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
	{
	print fmt("event dns_MX_reply");
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string)
	{
	print fmt("event dns_TXT_REPLY");
	}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	print fmt("event dns_SRV_reply");
	}

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	print fmt("event dns_EDNS_addl");
	}

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
	{
	print fmt("event dns_TSIG_addl");
	}

event dns_end(c: connection, msg: dns_msg)
	{
	print fmt("event dns_end");
	}

event dns_full_request()
	{
	print fmt("event dns_full_request");
	}



event bro_done()
        {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
        }
