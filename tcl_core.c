/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */
 
#include "mod_tcl.h"

static void tcl_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp);
static apr_status_t tcl_cleanup(void *data);
static void tcl_init_handler(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void* tcl_create_dir_config(apr_pool_t *p, char *d);

/* 0  */ static int tcl_handler(request_rec *r);
/* 1  */ static int tcl_post_read_request(request_rec *r);
/* 2  */ static int tcl_translate_name(request_rec *r);
/* 3  */ static int tcl_header_parser(request_rec *r);
/* 4  */ static int tcl_access_checker(request_rec *r);
/* 5  */ static int tcl_check_user_id(request_rec *r);
/* 6  */ static int tcl_auth_checker(request_rec *r);
/* 7  */ static int tcl_type_checker(request_rec *r);
/* 8  */ static int tcl_fixups(request_rec *r);
/* 9  */ static int tcl_log_transaction(request_rec *r);

static const char* add_hand(cmd_parms *parms, void *mconfig, const char *arg);
static const char* sfl(cmd_parms *parms, void *mconfig, int flag);
static const char* tcl_set(cmd_parms *parms, void *mconfig, const char *one, const char *two, const char *three);
static const char* tcl_setlist(cmd_parms *parms, void *mconfig, const char *one, const char *two);
static const char* tcl_raw_args(cmd_parms *parms, void *mconfig, char *arg);
static const char *tcl_no_args(cmd_parms *parms, void *mconfig);

typedef const char* (*fz_t)(void);

#define NUM_HANDLERS 10

static const command_rec tcl_commands[] = {
	AP_INIT_FLAG(		"Tcl",							(fz_t) sfl,				(void*) 1,	OR_AUTHCFG,		"turn mod_tcl on or off." ),
	AP_INIT_TAKE23(		"Tcl_Var",						(fz_t) tcl_set,			NULL,		OR_AUTHCFG,		"set global variables in TCL." ),
	AP_INIT_TAKE2(		"Tcl_ListVar",					(fz_t) tcl_setlist,		NULL,		OR_AUTHCFG,		"set global list variables." ),
	
	/* this may be phased out, it should now be, Tcl_ContentHandler */
	AP_INIT_TAKE1(		"Tcl_ContentHandlers",			(fz_t) add_hand,		(void*) 0,	OR_AUTHCFG,		"add content handler." ),
	
	AP_INIT_TAKE1(		"Tcl_ContentHandler",			(fz_t) add_hand,		(void*) 0,	OR_AUTHCFG,		"add content handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Post_Read_Request",	(fz_t) add_hand,		(void*) 1,	OR_AUTHCFG,		"add post_read_request handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Translate_Name",		(fz_t) add_hand,		(void*) 2,	OR_AUTHCFG,		"add translate_name handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Header_Parser",		(fz_t) add_hand,		(void*) 3,	OR_AUTHCFG,		"add header_parser handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Access_Checker",		(fz_t) add_hand,		(void*) 4,	OR_AUTHCFG,		"add access_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Check_User_ID",		(fz_t) add_hand,		(void*) 5,	OR_AUTHCFG,		"add check_user_id handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Auth_Checker",		(fz_t) add_hand,		(void*) 6,	OR_AUTHCFG,		"add auth_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Type_Checker",		(fz_t) add_hand,		(void*) 7,	OR_AUTHCFG,		"add type_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Fixups",				(fz_t) add_hand,		(void*) 8,	OR_AUTHCFG,		"add fixups handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Log_Transaction",		(fz_t) add_hand,		(void*) 9,	OR_AUTHCFG,		"add log_transaction handlers." ),
	AP_INIT_RAW_ARGS(	"<Tcl>",						(fz_t) tcl_raw_args,	NULL,		OR_AUTHCFG,		"add raw tcl to the interpreter." ),
	AP_INIT_NO_ARGS(	"</Tcl>",						(fz_t) tcl_no_args,		NULL,		OR_AUTHCFG,		"end of tcl section." ),
	{ NULL }
};

static handler_rec tcl_handlers[] = {
	{ "tcl-handler",		tcl_handler },
	{ NULL,					NULL }
};

static void register_hooks(void)
{
	ap_hook_pre_config(tcl_init, NULL, NULL, AP_HOOK_REALLY_FIRST);
	ap_hook_post_config(tcl_init_handler, NULL, NULL, AP_HOOK_MIDDLE);
	
//	ap_hook_post_read_request(tcl_post_read_request, NULL, NULL, AP_HOOK_MIDDLE);
//	ap_hook_translate_name(tcl_translate_name, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_header_parser(tcl_header_parser, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_access_checker(tcl_access_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_check_user_id(tcl_check_user_id, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_auth_checker(tcl_auth_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_type_checker(tcl_type_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_fixups(tcl_fixups, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_log_transaction(tcl_log_transaction, NULL, NULL, AP_HOOK_MIDDLE);
}

AP_DECLARE_DATA module tcl_module = {
    STANDARD20_MODULE_STUFF,
    tcl_create_dir_config,			/* create per-directory config structure */
    NULL,							/* merge per-directory config structures */
    NULL,							/* create per-server config structure */
    NULL,							/* merge per-server config structures */
    tcl_commands,					/* command apr_table_t */
    tcl_handlers,					/* handlers */
    register_hooks					/* register hooks */
};

typedef struct {
	char	*var1, *var2, *var3;
	int		fl;
} var_cache;

typedef struct {
	int					fl;
	char				*handlers[NUM_HANDLERS];
	apr_array_header_t	*var_list;
	apr_array_header_t	*raw_list;
} tcl_config_rec;

static void* tcl_create_dir_config(apr_pool_t *p, char *d)
{
	int i;
	tcl_config_rec *tclr = (tcl_config_rec*) apr_pcalloc(p, sizeof(tcl_config_rec));
	
	tclr->fl		= 0;
	tclr->var_list	= apr_make_array(p, 0, sizeof(var_cache));
	tclr->raw_list	= apr_make_array(p, 0, sizeof(char*));
	
	memset(tclr->handlers, 0, NUM_HANDLERS * sizeof(char*));
	
	return tclr;
}

static const char* add_hand(cmd_parms *parms, void *mconfig, const char* arg)
{
	int pos = (int) parms->info;
	tcl_config_rec *tclr = (tcl_config_rec*) mconfig;
	
	tclr->handlers[pos] = apr_pstrdup(parms->pool, arg);
	
	return NULL;
}

static const char* sfl(cmd_parms *parms, void *mconfig, int flag)
{
	int f = (int) parms->info;
	tcl_config_rec *tclr = (tcl_config_rec*) mconfig;
	
	if (flag) {
		tclr->fl |= f;
	}
	else {
		tclr->fl &= ~f;
	}
	
	return NULL;
}

static const char* tcl_set(cmd_parms *parms, void *mconfig, const char *one, const char *two, const char *three)
{
	tcl_config_rec *tclr = (tcl_config_rec*) mconfig;
	char *ptr2, *ptr3;
	var_cache *var = (var_cache*) apr_push_array(tclr->var_list);
	
	if (three == NULL) {
		ptr2 = NULL;
		ptr3 = (char*) two;
	}
	else {
		ptr2 = (char*) two;
		ptr3 = (char*) three;
	}
	
	var->var1 = apr_pstrdup(parms->pool, one);
	var->var2 = apr_pstrdup(parms->pool, ptr2);
	var->var3 = apr_pstrdup(parms->pool, ptr3);
	
	var->fl = 1;
	
	return NULL;
}

static const char* tcl_setlist(cmd_parms *parms, void *mconfig, const char *one, const char *two)
{
	tcl_config_rec *tclr = (tcl_config_rec*) mconfig;
	var_cache *var = (var_cache*) apr_push_array(tclr->var_list);
	
	var->var1 = apr_pstrdup(parms->pool, one);
	var->var2 = apr_pstrdup(parms->pool, two);
	
	var->fl = 2;
	
	return NULL;
}

static const char *tcl_raw_args(cmd_parms *parms, void *mconfig, char *arg)
{
	tcl_config_rec *tclr = (tcl_config_rec*) mconfig;
	char l[MAX_STRING_LEN];
	char **line, *script, **xx;
	int i, j = 0, k = 0;
	apr_array_header_t *temp = apr_make_array(parms->pool, 0, sizeof(char*));
	char **temp_elts = (char**) temp->elts;

	while (!(ap_cfg_getline(l, MAX_STRING_LEN, parms->config_file))) {
		if (!strncasecmp(l, "</Tcl>", 6)) {
			goto cleanup;
		}

		line = (char**) apr_push_array(temp);
		j += asprintf(line, l);
		k++;
	}
	
  cleanup:
  
	script = (char*) malloc(j + k + 1);
	j = 0;
	
	for (i = 0; i < temp->nelts; i++) {
		memcpy(&(script[j]), temp_elts[i], j += strlen(temp_elts[i]));
		script[j] = '\n';
		j++;
		
		free(temp_elts[i]);
	}
	
	script[j] = '\0';
	
	xx = (char**) apr_push_array(tclr->raw_list);
	*xx = apr_pstrdup(parms->pool, script);
	
	free(script);

	return NULL;
}

static const char *tcl_no_args(cmd_parms *parms, void *dummy)
{
	return NULL;
}

void run_script(Tcl_Interp* interp, char *fmt, ...)
{
	char *bptr = NULL;
	va_list va;
	Tcl_Obj *obj;
	
	va_start(va, fmt);
	vasprintf(&bptr, fmt, va);
	va_end(va);
	
	obj = Tcl_NewStringObj(bptr, -1);
	
	if (Tcl_EvalObjEx(interp, obj, 0) == TCL_ERROR) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_EvalObjEx(%s): %s", bptr, Tcl_GetStringResult(interp));
	}
	
	free(bptr);
}

void set_var(Tcl_Interp* interp, char *var1, char *var2, const char *fmt, ...)
{
	char *bptr;
	va_list va;
	Tcl_Obj *obj;
	
	va_start(va, fmt);
	vasprintf(&bptr, fmt, va);
	va_end(va);
	
	obj = Tcl_NewStringObj(bptr, -1);
	
	if (Tcl_SetVar2Ex(interp, var1, var2, obj, TCL_LEAVE_ERR_MSG) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_SetVarEx2(%s, %s, %s): %s", var1, var2 ? var2 : "NULL", bptr, Tcl_GetStringResult(interp));
	}
	
	free(bptr);
}

void set_vari(Tcl_Interp* interp, char *var1, char *var2, int var)
{	
	if (Tcl_SetVar2Ex(interp, var1, var2, Tcl_NewIntObj(var), TCL_LEAVE_ERR_MSG) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_SetVarEx2(%s, %s, %d): %s", var1, var2 ? var2 : "NULL", var, Tcl_GetStringResult(interp));
	}
}

void set_varb(Tcl_Interp* interp, char *var1, char *var2, char *data, int len)
{
	Tcl_Obj *obj;
	
	obj = Tcl_NewByteArrayObj(data, len);
	
	if (Tcl_SetVar2Ex(interp, var1, var2, obj, TCL_LEAVE_ERR_MSG) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_SetVarEx2(%s, %s, %s): %s", var1, var2 ? var2 : "NULL", "*data*", Tcl_GetStringResult(interp));
	}
}

typedef struct {
	char			*file;
	struct stat		st;
} file_cache;

Tcl_Interp			*interp = NULL;
apr_array_header_t	*fcache = NULL;
apr_pool_t			*_pconf = NULL;
request_rec			*_r = NULL;
char				*current_namespace = NULL;
int					read_post_ok;

static void tcl_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
	char *buf;
	
	_pconf = pconf;
	fcache = apr_make_array(pconf, 0, sizeof(file_cache));
	
	interp = Tcl_CreateInterp();
	
	if (Tcl_Init(interp) == TCL_ERROR) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_Init(0x%x): %s", interp, Tcl_GetStringResult(interp));
		exit(1);
	}
	
	apr_register_cleanup(pconf, NULL, tcl_cleanup, apr_null_cleanup);
	
	/* misc util */
	Tcl_CreateObjCommand(interp, "apache::abort", cmd_abort, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::read_post", cmd_read_post, NULL, NULL);
	
	Tcl_CreateObjCommand(interp, "apache::random", cmd_random, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::srandom", cmd_srandom, NULL, NULL);
	
	Tcl_CreateObjCommand(interp, "apache::base64_encode", cmd_base64_encode, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::base64_decode", cmd_base64_decode, NULL, NULL);
	
	/* read and set stuff from request_rec */
	Tcl_CreateObjCommand(interp, "apache::r", cmd_r, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::r_set", cmd_r_set, NULL, NULL);
	
	/* http_core.h */
	Tcl_CreateObjCommand(interp, "apache::ap_allow_options", cmd_ap_allow_options, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_allow_overrides", cmd_ap_allow_overrides, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_default_type", cmd_ap_default_type, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_document_root", cmd_ap_document_root, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_remote_host", cmd_ap_get_remote_host, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_remote_logname", cmd_ap_get_remote_logname, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_construct_url", cmd_ap_construct_url, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_server_name", cmd_ap_get_server_name, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_server_port", cmd_ap_get_server_port, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_limit_req_body", cmd_ap_get_limit_req_body, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_limit_xml_body", cmd_ap_get_limit_xml_body, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_custom_response", cmd_ap_custom_response, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_exists_config_define", cmd_ap_exists_config_define, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_auth_type", cmd_ap_auth_type, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_auth_name", cmd_ap_auth_name, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_satisfies", cmd_ap_satisfies, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_requires", cmd_ap_requires, NULL, NULL);
	
	/* http_log.h */
	Tcl_CreateObjCommand(interp, "apache::ap_log_error", cmd_ap_log_error, NULL, NULL);
	
	/* http_protocol.h */
	Tcl_CreateObjCommand(interp, "apache::ap_send_http_header", cmd_ap_send_http_header, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_send_http_trace", cmd_ap_send_http_trace, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_send_http_options", cmd_ap_send_http_options, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_finalize_request_protocol", cmd_ap_finalize_request_protocol, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_send_error_response", cmd_ap_send_error_response, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_set_content_length", cmd_ap_set_content_length, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_set_keepalive", cmd_ap_set_keepalive, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_rationalize_mtime", cmd_ap_rationalize_mtime, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_make_etag", cmd_ap_make_etag, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_set_etag", cmd_ap_set_etag, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_set_last_modified", cmd_ap_set_last_modified, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_meets_conditions", cmd_ap_meets_conditions, NULL, NULL);
	/**/
	Tcl_CreateObjCommand(interp, "apache::rputs", cmd_rputs, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::rwrite", cmd_rwrite, NULL, NULL);
	/**/
	Tcl_CreateObjCommand(interp, "apache::ap_rputs", cmd_rputs, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_rwrite", cmd_rwrite, NULL, NULL);
	/**/
	Tcl_CreateObjCommand(interp, "apache::ap_rflush", cmd_ap_rflush, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_status_line", cmd_ap_get_status_line, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_setup_client_block", cmd_ap_setup_client_block, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_client_block", cmd_ap_get_client_block, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_discard_request_body", cmd_ap_discard_request_body, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_note_auth_failure", cmd_ap_note_auth_failure, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_note_basic_auth_failure", cmd_ap_note_basic_auth_failure, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_note_digest_auth_failure", cmd_ap_note_digest_auth_failure, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_basic_auth_pw", cmd_ap_get_basic_auth_pw, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_parse_uri", cmd_ap_parse_uri, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_method_number_of", cmd_ap_method_number_of, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_method_name_of", cmd_ap_method_name_of, NULL, NULL);

	/* http_request.h */
	Tcl_CreateObjCommand(interp, "apache::ap_internal_redirect", cmd_ap_internal_redirect, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_internal_redirect_handler", cmd_ap_internal_redirect_handler, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_some_auth_required", cmd_ap_some_auth_required, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_update_mtime", cmd_ap_update_mtime, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_allow_methods", cmd_ap_allow_methods, NULL, NULL);

	/* httpd.h */
	Tcl_CreateObjCommand(interp, "apache::ap_get_server_version", cmd_ap_get_server_version, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_add_version_component", cmd_ap_add_version_component, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apache::ap_get_server_built", cmd_ap_get_server_built, NULL, NULL);
	
	/* util_script.h */
	Tcl_CreateObjCommand(interp, "apache::ap_create_environment", cmd_ap_create_environment, NULL, NULL);
	
	// provided nasty
	buf = "\
	proc apache::output { script } {\n\
		set script [split $script \\n]\n\
		\n\
		foreach i $script {\n\
			if { $i != \"\" } {\n\
				regsub -all {\\\"} $i {\\\"} i\n\
				uplevel 1 rputs \\\"$i\\\"\n\
			}\n\
		}\n\
	}";
						
	run_script(interp, buf);

	set_vari(interp, "apache::DECLINED", NULL, DECLINED);
	set_vari(interp, "apache::DONE", NULL, DONE);
	set_vari(interp, "apache::OK", NULL, OK);
	
	/* legacy */
	set_vari(interp, "apache::BAD_REQUEST", NULL, HTTP_BAD_REQUEST);
	set_vari(interp, "apache::REDIRECT", NULL, HTTP_MOVED_TEMPORARILY);
	set_vari(interp, "apache::SERVER_ERROR", NULL, HTTP_INTERNAL_SERVER_ERROR);
	set_vari(interp, "apache::NOT_FOUND", NULL, HTTP_NOT_FOUND);
	
	set_vari(interp, "apache::M_POST", NULL, M_POST);
	set_vari(interp, "apache::M_GET", NULL, M_GET);
	set_vari(interp, "apache::M_PUT", NULL, M_PUT);
	set_vari(interp, "apache::M_DELETE", NULL, M_DELETE);
	set_vari(interp, "apache::M_CONNECT", NULL, M_CONNECT);
	set_vari(interp, "apache::M_OPTIONS", NULL, M_OPTIONS);
	set_vari(interp, "apache::M_TRACE", NULL, M_TRACE);
	set_vari(interp, "apache::M_PATCH", NULL, M_PATCH);
	set_vari(interp, "apache::M_PROPFIND", NULL, M_PROPFIND);
	set_vari(interp, "apache::M_PROPPATCH", NULL, M_PROPPATCH);
	set_vari(interp, "apache::M_MKCOL", NULL, M_MKCOL);
	set_vari(interp, "apache::M_COPY", NULL, M_COPY);
	set_vari(interp, "apache::M_MOVE", NULL, M_MOVE);
	set_vari(interp, "apache::M_LOCK", NULL, M_LOCK);
	set_vari(interp, "apache::M_UNLOCK", NULL, M_UNLOCK);
	set_vari(interp, "apache::M_INVALID", NULL, M_INVALID);
	
	set_vari(interp, "apache::HTTP_CONTINUE", NULL, HTTP_CONTINUE);
	set_vari(interp, "apache::HTTP_SWITCHING_PROTOCOLS", NULL, HTTP_SWITCHING_PROTOCOLS);
	set_vari(interp, "apache::HTTP_PROCESSING", NULL, HTTP_PROCESSING);
	set_vari(interp, "apache::HTTP_OK", NULL, HTTP_OK);
	set_vari(interp, "apache::HTTP_CREATED", NULL, HTTP_CREATED);
	set_vari(interp, "apache::HTTP_ACCEPTED", NULL, HTTP_ACCEPTED);
	set_vari(interp, "apache::HTTP_NON_AUTHORITATIVE", NULL, HTTP_NON_AUTHORITATIVE);
	set_vari(interp, "apache::HTTP_NO_CONTENT", NULL, HTTP_NO_CONTENT);
	set_vari(interp, "apache::HTTP_RESET_CONTENT", NULL, HTTP_RESET_CONTENT);
	set_vari(interp, "apache::HTTP_PARTIAL_CONTENT", NULL, HTTP_PARTIAL_CONTENT);
	set_vari(interp, "apache::HTTP_MULTI_STATUS", NULL, HTTP_MULTI_STATUS);
	set_vari(interp, "apache::HTTP_MULTIPLE_CHOICES", NULL, HTTP_MULTIPLE_CHOICES);
	set_vari(interp, "apache::HTTP_MOVED_PERMANENTLY", NULL, HTTP_MOVED_PERMANENTLY);
	set_vari(interp, "apache::HTTP_MOVED_TEMPORARILY", NULL, HTTP_MOVED_TEMPORARILY);
	set_vari(interp, "apache::HTTP_SEE_OTHER", NULL, HTTP_SEE_OTHER);
	set_vari(interp, "apache::HTTP_NOT_MODIFIED", NULL, HTTP_NOT_MODIFIED);
	set_vari(interp, "apache::HTTP_USE_PROXY", NULL, HTTP_USE_PROXY);
	set_vari(interp, "apache::HTTP_TEMPORARY_REDIRECT", NULL, HTTP_TEMPORARY_REDIRECT);
	set_vari(interp, "apache::HTTP_BAD_REQUEST", NULL, HTTP_BAD_REQUEST);
	set_vari(interp, "apache::HTTP_UNAUTHORIZED", NULL, HTTP_UNAUTHORIZED);
	set_vari(interp, "apache::HTTP_PAYMENT_REQUIRED", NULL, HTTP_PAYMENT_REQUIRED);
	set_vari(interp, "apache::HTTP_FORBIDDEN", NULL, HTTP_FORBIDDEN);
	set_vari(interp, "apache::HTTP_NOT_FOUND", NULL, HTTP_NOT_FOUND);
	set_vari(interp, "apache::HTTP_METHOD_NOT_ALLOWED", NULL, HTTP_METHOD_NOT_ALLOWED);
	set_vari(interp, "apache::HTTP_NOT_ACCEPTABLE", NULL, HTTP_NOT_ACCEPTABLE);
	set_vari(interp, "apache::HTTP_PROXY_AUTHENTICATION_REQUIRED", NULL, HTTP_PROXY_AUTHENTICATION_REQUIRED);
	set_vari(interp, "apache::HTTP_REQUEST_TIME_OUT", NULL, HTTP_REQUEST_TIME_OUT);
	set_vari(interp, "apache::HTTP_CONFLICT", NULL, HTTP_CONFLICT);
	set_vari(interp, "apache::HTTP_GONE", NULL, HTTP_GONE);
	set_vari(interp, "apache::HTTP_LENGTH_REQUIRED", NULL, HTTP_LENGTH_REQUIRED);
	set_vari(interp, "apache::HTTP_PRECONDITION_FAILED", NULL, HTTP_PRECONDITION_FAILED);
	set_vari(interp, "apache::HTTP_REQUEST_ENTITY_TOO_LARGE", NULL, HTTP_REQUEST_ENTITY_TOO_LARGE);
	set_vari(interp, "apache::HTTP_REQUEST_URI_TOO_LARGE", NULL, HTTP_REQUEST_URI_TOO_LARGE);
	set_vari(interp, "apache::HTTP_UNSUPPORTED_MEDIA_TYPE", NULL, HTTP_UNSUPPORTED_MEDIA_TYPE);
	set_vari(interp, "apache::HTTP_RANGE_NOT_SATISFIABLE", NULL, HTTP_RANGE_NOT_SATISFIABLE);
	set_vari(interp, "apache::HTTP_EXPECTATION_FAILED", NULL, HTTP_EXPECTATION_FAILED);
	set_vari(interp, "apache::HTTP_UNPROCESSABLE_ENTITY", NULL, HTTP_UNPROCESSABLE_ENTITY);
	set_vari(interp, "apache::HTTP_LOCKED", NULL, HTTP_LOCKED);
	set_vari(interp, "apache::HTTP_FAILED_DEPENDENCY", NULL, HTTP_FAILED_DEPENDENCY);
	set_vari(interp, "apache::HTTP_INTERNAL_SERVER_ERROR", NULL, HTTP_INTERNAL_SERVER_ERROR);
	set_vari(interp, "apache::HTTP_NOT_IMPLEMENTED", NULL, HTTP_NOT_IMPLEMENTED);
	set_vari(interp, "apache::HTTP_BAD_GATEWAY", NULL, HTTP_BAD_GATEWAY);
	set_vari(interp, "apache::HTTP_SERVICE_UNAVAILABLE", NULL, HTTP_SERVICE_UNAVAILABLE);
	set_vari(interp, "apache::HTTP_GATEWAY_TIME_OUT", NULL, HTTP_GATEWAY_TIME_OUT);
	set_vari(interp, "apache::HTTP_VERSION_NOT_SUPPORTED", NULL, HTTP_VERSION_NOT_SUPPORTED);
	set_vari(interp, "apache::HTTP_VARIANT_ALSO_VARIES", NULL, HTTP_VARIANT_ALSO_VARIES);
	set_vari(interp, "apache::HTTP_INSUFFICIENT_STORAGE", NULL, HTTP_INSUFFICIENT_STORAGE);
	set_vari(interp, "apache::HTTP_NOT_EXTENDED", NULL, HTTP_NOT_EXTENDED);
	
	set_vari(interp, "apache::REMOTE_HOST", NULL, REMOTE_HOST);
	set_vari(interp, "apache::REMOTE_NAME", NULL, REMOTE_NAME);
	set_vari(interp, "apache::REMOTE_NOLOOKUP", NULL, REMOTE_NOLOOKUP);
	set_vari(interp, "apache::REMOTE_DOUBLE_REV", NULL, REMOTE_DOUBLE_REV);
	
	set_vari(interp, "apache::APLOG_EMERG", NULL, APLOG_EMERG);
	set_vari(interp, "apache::APLOG_ALERT", NULL, APLOG_ALERT);
	set_vari(interp, "apache::APLOG_CRIT", NULL, APLOG_CRIT);
	set_vari(interp, "apache::APLOG_ERR", NULL, APLOG_ERR);
	set_vari(interp, "apache::APLOG_WARNING", NULL, APLOG_WARNING);
	set_vari(interp, "apache::APLOG_NOTICE", NULL, APLOG_NOTICE);
	set_vari(interp, "apache::APLOG_INFO", NULL, APLOG_INFO);
	set_vari(interp, "apache::APLOG_DEBUG", NULL, APLOG_DEBUG);
	set_vari(interp, "apache::APLOG_NOERRNO", NULL, APLOG_NOERRNO);

	set_vari(interp, "apache::REQUEST_NO_BODY", NULL, REQUEST_NO_BODY);
	set_vari(interp, "apache::REQUEST_CHUNKED_ERROR", NULL, REQUEST_CHUNKED_ERROR);
	set_vari(interp, "apache::REQUEST_CHUNKED_DECHUNK", NULL, REQUEST_CHUNKED_DECHUNK);
	
	buf = "\
	namespace eval apache {\
		namespace export *\
	}";
	
	run_script(interp, buf);
}

static apr_status_t tcl_cleanup(void *data)
{
	if (interp) {
		Tcl_DeleteInterp(interp);
		interp = NULL;
	}
	
	return APR_SUCCESS;
}

static void tcl_init_handler(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ap_add_version_component(pconf, "mod_tcl/1.0d5");
}

static int run_handler(request_rec *r, int hh)
{
	int xx = HTTP_NOT_FOUND, i;
	tcl_config_rec *tclr = (tcl_config_rec*) ap_get_module_config(r->per_dir_config, &tcl_module);
	size_t flen = strlen(r->filename);
	file_cache *fptr = NULL, *fa = (file_cache*) fcache->elts;
	var_cache *vl = (var_cache*) tclr->var_list->elts;
	char **rl = (char**) tclr->raw_list->elts;
	struct stat st;
	
	if (!(tclr->fl & 1) || !interp) {
		return DECLINED;
	}
	
	/* handler wasn't set so ignore it */
	if (!tclr->handlers[hh]) {
		return DECLINED;
	}
	
	stat(r->filename, &st);
	
	for (i = 0; i < fcache->nelts; i++) {
		if (!strcmp(fa[i].file, r->filename)) {
			fptr = &(fa[i]);
			break;
		}
	}

	if (!fptr) {
		int fd;
		void *mptr;
		char *bptr;
		off_t pos = 0;
		Tcl_Obj *obj;
		
		if ((fd = open(r->filename, O_RDONLY, 0)) == -1) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "open(%s, ...): %s", r->filename, strerror(errno));
			
			return HTTP_NOT_FOUND;
		}

#ifdef HAVE_MMAP
		mptr = mmap((caddr_t) 0, r->finfo.size, PROT_READ, MAP_SHARED, fd, 0);
#else
		mptr = malloc(r->finfo.size);
		read(fd, mptr, r->finfo.size);
#endif /* HAVE_MMAP */

		bptr = (char*) malloc(r->finfo.size + flen + 21);
		
		memcpy(bptr, "namespace eval ", 15);		pos += 15;
		memcpy(bptr + pos, r->filename, flen);		pos += flen;
		memcpy(bptr + pos, " {\n", 3);				pos += 3;
		memcpy(bptr + pos, mptr, r->finfo.size);	pos += r->finfo.size;
		memcpy(bptr + pos, "\n}\0", 3);
		
#ifdef HAVE_MMAP
		munmap((char*) mptr, r->finfo.size);
#else
		free(mptr);
#endif /* HAVE_MMAP */

		close(fd);
		
		fptr = (file_cache*) apr_push_array(fcache);
		
		fptr->file = apr_pstrdup(fcache->cont, r->filename);
		memcpy(&(fptr->st), &st, sizeof(struct stat));
		
		obj = Tcl_NewStringObj(bptr, -1);
		
		free(bptr);
		
		if (Tcl_EvalObjEx(interp, obj, 0) == TCL_ERROR) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Tcl_EvalObjEx(...): %s\n%s", Tcl_GetStringResult(interp), Tcl_GetVar(interp, "errorInfo", 0));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		
		for (i = 0; i < tclr->var_list->nelts; i++) {
			if (vl[i].fl == 1) {
				char *namespc = (char*) malloc(strlen(r->filename) + strlen(vl[i].var1) + 3);
				
				sprintf(namespc, "%s::%s", r->filename, vl[i].var1);
				set_var(interp, namespc, vl[i].var2, vl[i].var3);
				free(namespc);
			}
			else if (vl[i].fl == 2) {
				char *namespc = (char*) malloc(strlen(r->filename) + strlen(vl[i].var1) + 3);
				
				sprintf(namespc, "%s::%s", r->filename, vl[i].var1);
				run_script(interp, "lappend %s %s", namespc, vl[i].var2);
				free(namespc);
			}
		}
		
		for (i = 0, pos = 0; i < tclr->raw_list->nelts; i++) {
			int rl_len = strlen(rl[i]);
			
			bptr = (char*) malloc(rl_len + flen + 21);
			
			memcpy(bptr, "namespace eval ", 15);		pos += 15;
			memcpy(bptr + pos, r->filename, flen);		pos += flen;
			memcpy(bptr + pos, " {\n", 3);				pos += 3;
			memcpy(bptr + pos, rl[i], rl_len);			pos += rl_len;
			memcpy(bptr + pos, "\n}\0", 3);
			
			obj = Tcl_NewStringObj(bptr, -1);
			
			free(bptr);
			
			if (Tcl_EvalObjEx(interp, obj, 0) == TCL_ERROR) {
				ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Tcl_EvalObjEx(...): %s\n%s", Tcl_GetStringResult(interp), Tcl_GetVar(interp, "errorInfo", 0));
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	}
	else if (st.st_mtime > fptr->st.st_mtime) {
		int fd;
		void *mptr;
		char *bptr;
		off_t pos = 0;
		Tcl_Obj *obj;
		
		if ((fd = open(r->filename, O_RDONLY, 0)) == -1) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "open(%s, ...): %s", r->filename, strerror(errno));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		
#ifdef HAVE_MMAP
		mptr = mmap((caddr_t) 0, r->finfo.size, PROT_READ, MAP_SHARED, fd, 0);
#else
		mptr = malloc(r->finfo.size);
		read(fd, mptr, f->finfo.size);
#endif /* HAVE_MMAP */

		bptr = malloc(r->finfo.size + flen + 21);
		
		memcpy(bptr, "namespace eval ", 15);		pos += 15;
		memcpy(bptr + pos, r->filename, flen);		pos += flen;
		memcpy(bptr + pos, " {\n", 3);				pos += 3;
		memcpy(bptr + pos, mptr, r->finfo.size);	pos += r->finfo.size;
		memcpy(bptr + pos, "\n}\0", 3);
		
#ifdef HAVE_MMAP
		munmap((char*) mptr, r->finfo.size);
#else
		free(mptr);
#endif /* HAVE_MMAP */

		close(fd);
		
		fptr = (file_cache*) apr_push_array(fcache);
		
		fptr->file = apr_pstrdup(fcache->cont, r->filename);
		memcpy(&(fptr->st), &st, sizeof(struct stat));
		
		obj = Tcl_NewStringObj(bptr, -1);
		
		free(bptr);
		
		if (Tcl_EvalObjEx(interp, obj, 0) == TCL_ERROR) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Tcl_EvalObjEx(...): %s\n%s", Tcl_GetStringResult(interp), Tcl_GetVar(interp, "errorInfo", 0));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	
	_r = r;
	current_namespace = r->filename;
	read_post_ok = 1;
	
	{
		char *eptr = (char*) malloc(strlen(tclr->handlers[hh]) + flen + 3);
		Tcl_Obj *obj;
		
		sprintf(eptr, "%s::%s", fptr->file, tclr->handlers[hh]);
		
		obj = Tcl_NewStringObj(eptr, -1);
		
		free(eptr);
		
		if (Tcl_EvalObjEx(interp, obj, 0) == TCL_ERROR) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Tcl_EvalObjEx(%s): %s", eptr, Tcl_GetStringResult(interp));
			
			r->content_type = "text/html";
			ap_send_http_header(r);
			
			ap_rprintf(r, "<H3>TCL Error</H3><BR><PRE>%s</PRE>", Tcl_GetString(Tcl_GetVar2Ex(interp, "errorInfo", NULL, 0)));
			
			return OK;
		}
		
		Tcl_GetIntFromObj(interp, Tcl_GetObjResult(interp), &xx);
	}
	
	return xx;
}

static int tcl_handler(request_rec *r)
{
	return run_handler(r, 0);
}

static int tcl_post_read_request(request_rec *r)
{
	return run_handler(r, 1);
}

static int tcl_translate_name(request_rec *r)
{
	return run_handler(r, 2);
}

static int tcl_header_parser(request_rec *r)
{
	return run_handler(r, 3);
}

static int tcl_access_checker(request_rec *r)
{
	return run_handler(r, 4);
}

static int tcl_check_user_id(request_rec *r)
{
	return run_handler(r, 5);
}

static int tcl_auth_checker(request_rec *r)
{
	return run_handler(r, 6);
}

static int tcl_type_checker(request_rec *r)
{
	return run_handler(r, 7);
}

static int tcl_fixups(request_rec *r)
{
	return run_handler(r, 8);
}

static int tcl_log_transaction(request_rec *r)
{
	return run_handler(r, 9);
}
