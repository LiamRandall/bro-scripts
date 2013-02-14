## dns-fire.bro
##
## Part of the Bro fire-scripts
## https://github.com/LiamRandall/bro-scripts/fire-scripts/README.md
## Upon firing of each event for the dns protocol simply print a line.

global dns_mapping_valid_count=0;
global dns_mapping_unverified_count=0;
global dns_mapping_new_name_count=0;
global dns_mapping_lost_name_count=0;
global dns_mapping_altered_count=0;
global dns_message_count=0;
global dns_request_count=0;
global dns_rejected_count=0;
global dns_query_reply_count=0;
global non_dns_request_count=0;
global dns_A_reply_count=0;
global dns_AAAA_reply_count=0;
global dns_A6_reply_count=0;
global dns_NS_reply_count=0;
global dns_CNAME_reply_count=0;
global dns_PTR_reply_count=0;
global dns_SOA_reply_count=0;
global dns_WKS_reply_count=0;
global dns_HINFO_reply_count=0;
global dns_MX_reply_count=0;
global dns_TXT_reply_count=0;
global dns_SRV_reply_count=0;
global dns_EDNS_addl_count=0;
global dns_TSIG_addl_count=0;
global dns_end_count=0;
global dns_full_request_count=0;

event dns_mapping_valid(dm: dns_mapping)
	{
	++dns_mapping_valid_count;
	}

event dns_mapping_unverified(dm: dns_mapping)
	{
	++dns_mapping_unverified_count;
	}

event dns_mapping_new_name(dm: dns_mapping)
	{
	++dns_mapping_new_name_count;
	}

event dns_mapping_lost_name(dm: dns_mapping)
	{
	++dns_mapping_lost_name_count;
	}

event dns_mapping_altered(dm: dns_mapping, old_addrs: addr_set, new_addrs: addr_set)
	{
	++dns_mapping_altered_count;
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	++dns_message_count;
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	++dns_request_count;
	}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	++dns_rejected_count;
	}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	++dns_query_reply_count;
	}

event non_dns_request(c: connection, msg: string)
	{
	++non_dns_request_count;
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	++dns_A_reply_count;
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	++dns_AAAA_reply_count;
	}

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	++dns_A6_reply_count;
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	++dns_NS_reply_count;
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	++dns_CNAME_reply_count;
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	++dns_PTR_reply_count;
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	++dns_SOA_reply_count;
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	++dns_WKS_reply_count;
	}

event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	++dns_HINFO_reply_count;
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
	{
	++dns_MX_reply_count;
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string)
	{
	++dns_TXT_reply_count;
	}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	++dns_SRV_reply_count;
	}

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	++dns_EDNS_addl_count;
	}

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
	{
	++dns_TSIG_addl_count;
	}

event dns_end(c: connection, msg: dns_msg)
	{
	++dns_end_count;
	}

event dns_full_request()
	{
	++dns_full_request_count;
	}



event bro_done()
        {
		print fmt("---------------------------------------------------------------");
		print fmt("Bro is done");
		print fmt("dns_mapping_valid_count: %s", dns_mapping_valid_count);
		print fmt("dns_mapping_unverified_count: %s", dns_mapping_unverified_count);
		print fmt("dns_mapping_new_name_count: %s", dns_mapping_new_name_count);
		print fmt("dns_mapping_lost_name_count: %s", dns_mapping_lost_name_count);
		print fmt("dns_mapping_altered_count: %s", dns_mapping_altered_count);
		print fmt("dns_message_count: %s", dns_message_count);
		print fmt("dns_request_count: %s", dns_request_count);
		print fmt("dns_rejected_count: %s", dns_rejected_count);
		print fmt("dns_query_reply_count: %s", dns_query_reply_count);
		print fmt("non_dns_request_count: %s", non_dns_request_count);
		print fmt("dns_A_reply_count: %s", dns_A_reply_count);
		print fmt("dns_AAAA_reply_count: %s", dns_AAAA_reply_count);
		print fmt("dns_A6_reply_count: %s", dns_A6_reply_count);
		print fmt("dns_NS_reply_count: %s", dns_NS_reply_count);
		print fmt("dns_CNAME_reply_count: %s", dns_CNAME_reply_count);
		print fmt("dns_PTR_reply_count: %s", dns_PTR_reply_count);
		print fmt("dns_SOA_reply_count: %s", dns_SOA_reply_count);
		print fmt("dns_WKS_reply_count: %s", dns_WKS_reply_count);
		print fmt("dns_HINFO_reply_count: %s", dns_HINFO_reply_count);
		print fmt("dns_MX_reply_count: %s", dns_MX_reply_count);
		print fmt("dns_TXT_reply_count: %s", dns_TXT_reply_count);
		print fmt("dns_SRV_reply_count: %s", dns_SRV_reply_count);
		print fmt("dns_EDNS_addl_count: %s", dns_EDNS_addl_count);
		print fmt("dns_TSIG_addl_count: %s", dns_TSIG_addl_count);
		print fmt("dns_end_count: %s", dns_end_count);
		print fmt("dns_full_request_count: %s", dns_full_request_count);
        }
