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

typedef const char* (*fz_t)(void);

#define NUM_HANDLERS 10

static const command_rec tcl_commands[] = {
	AP_INIT_FLAG(		"Tcl",							(fz_t) sfl,				(void*) 1,	OR_AUTHCFG,		"turn mod_tcl on or off." ),
	AP_INIT_TAKE23(		"Tcl_Var",						(fz_t) tcl_set,			NULL,		OR_AUTHCFG,		"set global variables in TCL." ),
	AP_INIT_TAKE2(		"Tcl_ListVar",					(fz_t) tcl_setlist,		NULL,		OR_AUTHCFG,		"set global list variables." ),
	AP_INIT_TAKE1(		"Tcl_ContentHandlers",			(fz_t) add_hand,		(void*) 0,	OR_AUTHCFG,		"add content handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Post_Read_Request",	(fz_t) add_hand,		(void*) 1,	OR_AUTHCFG,		"add post_read_request handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Translate_Name",		(fz_t) add_hand,		(void*) 2,	OR_AUTHCFG,		"add translate_name handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Header_Parser",		(fz_t) add_hand,		(void*) 3,	OR_AUTHCFG,		"add header_parser handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Access_Checker",		(fz_t) add_hand,		(void*) 4,	OR_AUTHCFG,		"add access_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Check_User_ID",		(fz_t) add_hand,		(void*) 5,	OR_AUTHCFG,		"add check_user_id handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Auth_Checker",		(fz_t) add_hand,		(void*) 6,	OR_AUTHCFG,		"add auth_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Type_Checker",		(fz_t) add_hand,		(void*) 7,	OR_AUTHCFG,		"add type_checker handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Fixups",				(fz_t) add_hand,		(void*) 8,	OR_AUTHCFG,		"add fixups handlers." ),
	AP_INIT_TAKE1(		"Tcl_Hook_Log_Transaction",		(fz_t) add_hand,		(void*) 9,	OR_AUTHCFG,		"add log_transaction handlers." ),
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
/*	
	ap_hook_post_read_request(tcl_post_read_request, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_translate_name(tcl_translate_name, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_header_parser(tcl_header_parser, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_access_checker(tcl_access_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_check_user_id(tcl_check_user_id, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_auth_checker(tcl_auth_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_type_checker(tcl_type_checker, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_fixups(tcl_fixups, NULL, NULL, AP_HOOK_MIDDLE);
	ap_hook_log_transaction(tcl_log_transaction, NULL, NULL, AP_HOOK_MIDDLE);
*/
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
} tcl_config_rec;

static void* tcl_create_dir_config(apr_pool_t *p, char *d)
{
	int i;
	tcl_config_rec *tclr = (tcl_config_rec*) apr_pcalloc(p, sizeof(tcl_config_rec));
	
	tclr->fl		= 0;
	tclr->var_list	= apr_make_array(p, 0, sizeof(var_cache));
	
	for (i = 0; i < NUM_HANDLERS; i++) {
		tclr->handlers[i] = NULL;
	}
	
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

void set_var(Tcl_Interp* interp, const char *var1, const char *var2, const char *fmt, ...)
{
	char *bptr;
	va_list va;
	Tcl_Obj *obj;
	
	va_start(va, fmt);
	vasprintf(&bptr, fmt, va);
	va_end(va);
	
	obj = Tcl_NewStringObj(bptr, -1);
	
	if (Tcl_SetVar2Ex(interp, (char*) var1, (char*) var2, obj, TCL_LEAVE_ERR_MSG) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_SetVarEx2(%s, %s, %s): %s", var1, var2 ? var2 : "NULL", bptr, Tcl_GetStringResult(interp));
	}
	
	free(bptr);
}

void set_var2(Tcl_Interp* interp, const char *var1, const char *var2, const char *data, int len)
{
	Tcl_Obj *obj;
	
	obj = Tcl_NewByteArrayObj((unsigned char*) data, len);
	
	if (Tcl_SetVar2Ex(interp, (char*) var1, (char*) var2, obj, TCL_LEAVE_ERR_MSG) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_SetVarEx2(%s, %s, %s): %s", var1, var2 ? var2 : "NULL", "*data*", Tcl_GetStringResult(interp));
	}
}

typedef struct {
	char			*file;
	struct stat		st;
} file_cache;

Tcl_Interp			*interp = NULL;
apr_array_header_t	*fcache = NULL;
request_rec			*_r = NULL;
char				*current_namespace = NULL;
int					read_post_ok;

static void tcl_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
	fcache = apr_make_array(pconf, 0, sizeof(file_cache));
	
	interp = Tcl_CreateInterp();
	
	if (Tcl_Init(interp) == TCL_ERROR) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "Tcl_Init(0x%x): %s", interp, Tcl_GetStringResult(interp));
		exit(1);
	}
	
	apr_register_cleanup(pconf, NULL, tcl_cleanup, apr_null_cleanup);

	set_var(interp, "BAD_REQUEST", NULL, "%d", HTTP_BAD_REQUEST);
	set_var(interp, "DECLINED", NULL, "%d", DECLINED);
	set_var(interp, "DONE", NULL, "%d", DONE);
	set_var(interp, "NOT_FOUND", NULL, "%d", HTTP_NOT_FOUND);
	set_var(interp, "OK", NULL, "%d", OK);
	set_var(interp, "REDIRECT", NULL, "%d", HTTP_MOVED_TEMPORARILY);
	set_var(interp, "SERVER_ERROR", NULL, "%d", HTTP_INTERNAL_SERVER_ERROR);
	
	set_var(interp, "M_POST", NULL, "%d", M_POST);
	set_var(interp, "M_GET", NULL, "%d", M_GET);
	set_var(interp, "M_PUT", NULL, "%d", M_PUT);
	set_var(interp, "M_DELETE", NULL, "%d", M_DELETE);
	set_var(interp, "M_CONNECT", NULL, "%d", M_CONNECT);
	set_var(interp, "M_OPTIONS", NULL, "%d", M_OPTIONS);
	set_var(interp, "M_TRACE", NULL, "%d", M_TRACE);
	set_var(interp, "M_PATCH", NULL, "%d", M_PATCH);
	set_var(interp, "M_PROPFIND", NULL, "%d", M_PROPFIND);
	set_var(interp, "M_PROPPATCH", NULL, "%d", M_PROPPATCH);
	set_var(interp, "M_MKCOL", NULL, "%d", M_MKCOL);
	set_var(interp, "M_COPY", NULL, "%d", M_COPY);
	set_var(interp, "M_MOVE", NULL, "%d", M_MOVE);
	set_var(interp, "M_LOCK", NULL, "%d", M_LOCK);
	set_var(interp, "M_UNLOCK", NULL, "%d", M_UNLOCK);
	set_var(interp, "M_INVALID", NULL, "%d", M_INVALID);
	
	set_var(interp, "HTTP_OK", NULL, "%d", HTTP_OK);
	set_var(interp, "HTTP_CREATED", NULL, "%d", HTTP_CREATED);
	set_var(interp, "HTTP_ACCEPTED", NULL, "%d", HTTP_ACCEPTED);
	set_var(interp, "HTTP_NON_AUTHORITATIVE", NULL, "%d", HTTP_NON_AUTHORITATIVE);
	set_var(interp, "HTTP_NO_CONTENT", NULL, "%d", HTTP_NO_CONTENT);
	set_var(interp, "HTTP_PARTIAL_CONTENT", NULL, "%d", HTTP_PARTIAL_CONTENT);
	set_var(interp, "HTTP_MULTIPLE_CHOICES", NULL, "%d", HTTP_MULTIPLE_CHOICES);
	set_var(interp, "HTTP_MOVED_PERMANENTLY", NULL, "%d", HTTP_MOVED_PERMANENTLY);
	set_var(interp, "HTTP_MOVED_TEMPORARILY", NULL, "%d", HTTP_MOVED_TEMPORARILY);
	set_var(interp, "HTTP_NOT_MODIFIED", NULL, "%d", HTTP_NOT_MODIFIED);
	set_var(interp, "HTTP_BAD_REQUEST", NULL, "%d", HTTP_BAD_REQUEST);
	set_var(interp, "HTTP_UNAUTHORIZED", NULL, "%d", HTTP_UNAUTHORIZED);
	set_var(interp, "HTTP_PAYMENT_REQUIRED", NULL, "%d", HTTP_PAYMENT_REQUIRED);
	set_var(interp, "HTTP_FORBIDDEN", NULL, "%d", HTTP_FORBIDDEN);
	set_var(interp, "HTTP_NOT_FOUND", NULL, "%d", HTTP_NOT_FOUND);
	set_var(interp, "HTTP_METHOD_NOT_ALLOWED", NULL, "%d", HTTP_METHOD_NOT_ALLOWED);
	set_var(interp, "HTTP_NOT_ACCEPTABLE", NULL, "%d", HTTP_NOT_ACCEPTABLE);
	set_var(interp, "HTTP_PROXY_AUTHENTICATION_REQUIRED", NULL, "%d", HTTP_PROXY_AUTHENTICATION_REQUIRED);
	set_var(interp, "HTTP_REQUEST_TIME_OUT", NULL, "%d", HTTP_REQUEST_TIME_OUT);
	set_var(interp, "HTTP_GONE", NULL, "%d", HTTP_GONE);
	set_var(interp, "HTTP_PRECONDITION_FAILED", NULL, "%d", HTTP_PRECONDITION_FAILED);
	set_var(interp, "HTTP_REQUEST_ENTITY_TOO_LARGE", NULL, "%d", HTTP_REQUEST_ENTITY_TOO_LARGE);
	set_var(interp, "HTTP_REQUEST_URI_TOO_LARGE", NULL, "%d", HTTP_REQUEST_URI_TOO_LARGE);
	set_var(interp, "HTTP_UNSUPPORTED_MEDIA_TYPE", NULL, "%d", HTTP_UNSUPPORTED_MEDIA_TYPE);
	set_var(interp, "HTTP_INTERNAL_SERVER_ERROR", NULL, "%d", HTTP_INTERNAL_SERVER_ERROR);
	set_var(interp, "HTTP_NOT_IMPLEMENTED", NULL, "%d", HTTP_NOT_IMPLEMENTED);
	set_var(interp, "HTTP_BAD_GATEWAY", NULL, "%d", HTTP_BAD_GATEWAY);
	set_var(interp, "HTTP_SERVICE_UNAVAILABLE", NULL, "%d", HTTP_SERVICE_UNAVAILABLE);
	set_var(interp, "HTTP_GATEWAY_TIME_OUT", NULL, "%d", HTTP_GATEWAY_TIME_OUT);
	set_var(interp, "HTTP_VERSION_NOT_SUPPORTED", NULL, "%d", HTTP_VERSION_NOT_SUPPORTED);
	set_var(interp, "HTTP_VARIANT_ALSO_VARIES", NULL, "%d", HTTP_VARIANT_ALSO_VARIES);
	
	set_var(interp, "REMOTE_HOST", NULL, "%d", REMOTE_HOST);
	set_var(interp, "REMOTE_NAME", NULL, "%d", REMOTE_NAME);
	set_var(interp, "REMOTE_NOLOOKUP", NULL, "%d", REMOTE_NOLOOKUP);
	set_var(interp, "REMOTE_DOUBLE_REV", NULL, "%d", REMOTE_DOUBLE_REV);
	
	Tcl_CreateObjCommand(interp, "r", cmd_r, NULL, NULL);
	Tcl_CreateObjCommand(interp, "r_set", cmd_r_set, NULL, NULL);
	Tcl_CreateObjCommand(interp, "rputs", cmd_rputs, NULL, NULL);
	Tcl_CreateObjCommand(interp, "rwrite", cmd_rwrite, NULL, NULL);
	
	/* sort this out later */
	Tcl_CreateObjCommand(interp, "ap_internal_redirect", cmd_ap_internal_redirect, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_send_http_header", cmd_ap_send_http_header, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_server_version", cmd_ap_get_server_version, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_create_environment", cmd_ap_create_environment, NULL, NULL);
	
	/* stuff from http_core.h */
	Tcl_CreateObjCommand(interp, "ap_allow_options", cmd_ap_allow_options, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_allow_overrides", cmd_ap_allow_overrides, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_default_type", cmd_ap_default_type, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_document_root", cmd_ap_document_root, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_remote_host", cmd_ap_get_remote_host, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_remote_logname", cmd_ap_get_remote_logname, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_construct_url", cmd_ap_construct_url, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_server_name", cmd_ap_get_server_name, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_server_port", cmd_ap_get_server_port, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_limit_req_body", cmd_ap_get_limit_req_body, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_get_limit_xml_body", cmd_ap_get_limit_xml_body, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_custom_response", cmd_ap_custom_response, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_exists_config_define", cmd_ap_exists_config_define, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_auth_type", cmd_ap_auth_type, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_auth_name", cmd_ap_auth_name, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_satisfies", cmd_ap_satisfies, NULL, NULL);
	Tcl_CreateObjCommand(interp, "ap_requires", cmd_ap_requires, NULL, NULL);
	
	Tcl_CreateObjCommand(interp, "abort", cmd_abort, NULL, NULL);
	Tcl_CreateObjCommand(interp, "read_post", cmd_read_post, NULL, NULL);
	
	Tcl_CreateObjCommand(interp, "random", cmd_random, NULL, NULL);
	Tcl_CreateObjCommand(interp, "srandom", cmd_srandom, NULL, NULL);
	
	Tcl_CreateObjCommand(interp, "base64_encode", cmd_base64_encode, NULL, NULL);
	Tcl_CreateObjCommand(interp, "base64_decode", cmd_base64_decode, NULL, NULL);
	
	// provided
	{
		char output_proc[] = "\
		proc output { script } {\n\
			set script [split $script \\n]\n\
			\n\
			foreach i $script {\n\
				if { $i != \"\" } {\n\
					regsub -all {\\\"} $i {\\\"} i\n\
					uplevel 1 rputs \\\"$i\\\"\n\
				}\n\
			}\n\
		}";
							
		run_script(interp, output_proc);
	}
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
	ap_add_version_component(pconf, "mod_tcl/1.0d1");
}

static int run_handler(request_rec *r, int hh)
{
	int xx = HTTP_NOT_FOUND, i;
	tcl_config_rec *tclr = (tcl_config_rec*) ap_get_module_config(r->per_dir_config, &tcl_module);
	size_t flen = strlen(r->filename);
	file_cache *fptr = NULL, *fa = (file_cache*) fcache->elts;
	var_cache *vl = (var_cache*) tclr->var_list->elts;
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
		
		mptr = mmap((caddr_t) 0, r->finfo.size, PROT_READ, MAP_SHARED, fd, 0);
		bptr = (char*) malloc(r->finfo.size + flen + 21);
		
		memcpy(bptr, "namespace eval ", 15);		pos += 15;
		memcpy(bptr + pos, r->filename, flen);		pos += flen;
		memcpy(bptr + pos, " {\n", 3);				pos += 3;
		memcpy(bptr + pos, mptr, r->finfo.size);	pos += r->finfo.size;
		memcpy(bptr + pos, "\n}\0", 3);
		
		munmap((char*) mptr, r->finfo.size);
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
		
		mptr = mmap((caddr_t) 0, r->finfo.size, PROT_READ, MAP_SHARED, fd, 0);
		bptr = malloc(r->finfo.size + flen + 21);
		
		memcpy(bptr, "namespace eval ", 15);		pos += 15;
		memcpy(bptr + pos, r->filename, flen);		pos += flen;
		memcpy(bptr + pos, " {\n", 3);				pos += 3;
		memcpy(bptr + pos, mptr, r->finfo.size);	pos += r->finfo.size;
		memcpy(bptr + pos, "\n}\0", 3);
		
		munmap((char*) mptr, r->finfo.size);
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

