#!/usr/local/bin/tclsh8.3

namespace import -force ::apache::*

proc dump_env { } {
	variable env
	variable pram
	
	set env_list [array names env]
	set prm_list [array names pram]
	
	rputs "<HR><B>Environment</B><BR><BR>"
	
	foreach i $env_list {
		rputs "$i=$env($i)<BR>"
	}
	
	rputs "<HR><B>Posted Variables</B><BR><BR>"
	
	foreach i $prm_list {
		rputs "$i=$pram($i)<BR>"
	}

	rputs "<HR>"
}

proc content_handler { } {
	variable ::apache::OK

	ap_create_environment
	ap_send_http_header

	dump_env

output {
<PRE>
[r allowed]
[r allowed_methods]
[r allowed_xmethods]
[r ap_auth_type]
[r args]
[r assbackwards]
[r boundary]
[r bytes_sent]
[r chunked]
[r clength]
[r content_encoding]
[r content_type]
[r err_headers_out]
[r expecting_100]
[r filename]
[r handler]
[r headers_in]
[r headers_out]
[r header_only]
[r hostname]
[r method]
[r method_number]
[r mtime]
[r notes]
[r no_cache]
[r no_local_copy]
[r parsed_uri]
[r path_info]
[r protocol]
[r proto_num]
[r proxyreq]
[r range]
[r read_body]
[r read_chunked]
[r read_length]
[r remaining]
[r request_time]
[r sent_bodyct]
[r status]
[r status_line]
[r subprocess_env]
[r the_request]
[r unparsed_uri]
[r uri]
[r user]
[r vlist_validator]

[r connection remote_ip]
[r connection remote_host]
[r connection remote_logname]
[r connection aborted]
[r connection doublereverse]
[r connection local_ip]
[r connection local_host]
[r connection id]
[r connection notes]

[r server defn_name]
[r server defn_line_number]
[r server server_admin]
[r server server_hostname]
[r server port]
[r server error_fname]
[r server loglevel]
[r server is_virtual]
[r server addrs]
[r server timeout]
[r server keep_alive_timeout]
[r server keep_alive_max]
[r server keep_alive]
[r server path]
[r server names]
[r server wild_names]
[r server limit_req_line]
[r server limit_req_fieldsize]
[r server limit_req_fields]
</PRE>
}

	return $OK
}
