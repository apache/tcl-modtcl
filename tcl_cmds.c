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

extern Tcl_Interp			*interp;
extern apr_array_header_t	*fcache;
extern request_rec			*_r;
extern char					*current_namespace;
extern int					read_post_ok;

const uint8_t base64[] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

const uint8_t inv_base64[128] =
{
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255,  62, 255, 255, 255,  63, 
	52,  53,  54,  55,  56,  57,  58,  59,
	60,  61, 255, 255, 255, 255, 255, 255, 
	255,   0,   1,   2,   3,   4,   5,   6,
	7,   8,   9,  10,  11,  12,  13,  14, 
	15,  16,  17,  18,  19,  20,  21,  22,
	23,  24,  25, 255, 255, 255, 255, 255, 
	255,  26,  27,  28,  29,  30,  31,  32,
	33,  34,  35,  36,  37,  38,  39,  40, 
	41,  42,  43,  44,  45,  46,  47,  48,
	49,  50,  51, 255, 255, 255, 255, 255,
};

static size_t is_base64_buf(uint8_t *buf, size_t buf_len)
{
	size_t i;

	for (i = 0; i < buf_len; i++) {
      /* Accept equal sign. */
		if (buf[i] == '=') {
			continue;
		}
      /* Don't accept anything else which isn't in base64. */
		if (buf[i] > 127) {
			break;
		}

		if (inv_base64[buf[i]] == 255) {
			break;
		}
	}

	return i;
}

static uint8_t* buf_to_base64(const uint8_t *buf, size_t buf_len)
{
	uint8_t *out;
	size_t i, j;
	uint32_t limb;

	out = (uint8_t*) malloc(((buf_len * 8 + 5) / 6) + 5);

	for (i = 0, j = 0, limb = 0; i + 2 < buf_len; i += 3, j += 4) {
		limb =
			((uint32_t) buf[i] << 16) |
			((uint32_t) buf[i + 1] << 8) |
			((uint32_t) buf[i + 2]);

		out[j] = base64[(limb >> 18) & 63];
		out[j + 1] = base64[(limb >> 12) & 63];
		out[j + 2] = base64[(limb >> 6) & 63];
		out[j + 3] = base64[(limb) & 63];
	}
  
	switch (buf_len - i) {
	  case 0:
		break;
	  case 1:
		limb = ((uint32_t) buf[i]);
		out[j++] = base64[(limb >> 2) & 63];
		out[j++] = base64[(limb << 4) & 63];
		out[j++] = '=';
		out[j++] = '=';
		break;
	  case 2:
		limb = ((uint32_t) buf[i] << 8) | ((uint32_t) buf[i + 1]);
		out[j++] = base64[(limb >> 10) & 63];
		out[j++] = base64[(limb >> 4) & 63];
		out[j++] = base64[(limb << 2) & 63];
		out[j++] = '=';
		break;
	  default:
		// something wonkey happened...
		break;
	}

	out[j] = '\0';

	return out;
}

static uint8_t* base64_to_buf(uint8_t *str, size_t *buf_len)
{
	uint8_t *buf;
	int i, j, len;
	uint32_t limb;

	len = strlen((char *) str);
	*buf_len = (len * 6 + 7) / 8;
	buf = (uint8_t*) malloc(*buf_len);
  
	for (i = 0, j = 0, limb = 0; i + 3 < len; i += 4) {
		if (str[i] == '=' || str[i + 1] == '=' || str[i + 2] == '=' || str[i + 3] == '=') {
			if (str[i] == '=' || str[i + 1] == '=') {
				break;
			}
          
			if (str[i + 2] == '=') {
				limb =
					((uint32_t) inv_base64[str[i]] << 6) |
					((uint32_t) inv_base64[str[i + 1]]);
				buf[j] = (uint8_t) (limb >> 4) & 0xff;
				j++;
			}
			else {
				limb =
					((uint32_t) inv_base64[str[i]] << 12) |
					((uint32_t) inv_base64[str[i + 1]] << 6) |
					((uint32_t) inv_base64[str[i + 2]]);
				buf[j] = (uint8_t) (limb >> 10) & 0xff;
				buf[j + 1] = (uint8_t) (limb >> 2) & 0xff;
				j += 2;
			}
		}
		else {
			limb =
				((uint32_t) inv_base64[str[i]] << 18) |
				((uint32_t) inv_base64[str[i + 1]] << 12) |
				((uint32_t) inv_base64[str[i + 2]] << 6) |
				((uint32_t) inv_base64[str[i + 3]]);
          
			buf[j] = (uint8_t) (limb >> 16) & 0xff;
			buf[j + 1] = (uint8_t) (limb >> 8) & 0xff;
			buf[j + 2] = (uint8_t) (limb) & 0xff;
			j += 3;
		}
	}

	*buf_len = j;
  
	return buf;
}

static uint8_t* base64_remove_whitespace(const uint8_t *str, size_t len)
{
	uint8_t *cp;
	size_t i, j;

	if (len == 0) {
		len = strlen((char *) str);
	}
	
	cp = (uint8_t*) malloc(len + 1);

	for (i = 0, j = 0; i < len; i++) {
		if (!(str[i] & 128)) {
			if (inv_base64[str[i]] != 255 || str[i] == '=') {
				cp[j++] = str[i];
			}
		}
	}

	cp[j] = '\0';
  
	return cp;
}

static char* mstrstr(char *haystack, char *needle, size_t n, size_t m)
{
	size_t i;
	
	if (m >= n) {
		if (!memcmp(haystack, needle, n)) {
			return haystack;
		}
		else {
			return NULL;
		}
	}
	
	for (i = 0; (i + m) < n; i++, haystack++) {
		if (!memcmp(haystack, needle, m)) {
			return haystack;
		}
	}
	
	return NULL;
}

static int read_post_data(request_rec *r, Tcl_Interp *interp, char *boundary)
{
	int rc, lpos = 0, blen = strlen(boundary);
	char *lbuf, *ptr;
	long remaining;
	
	if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
		return rc;
	}
	
	remaining = r->remaining;
	lbuf = (char*) apr_palloc(r->pool, remaining + 1);

	if (ap_should_client_block(r)) {
		char buf[HUGE_STRING_LEN];
		int len_read;
		
//		ap_hard_timeout("read_post_data", r);
		
		while ((len_read = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
//			ap_reset_timeout(r);
			
			memcpy(lbuf + lpos, buf, len_read);
			lpos += len_read;
		}
		
		lbuf[lpos] = '\0';
		
//		ap_kill_timeout(r);
	}
	
	ptr = strstr(lbuf, boundary);
	remaining -= (ptr - lbuf - sizeof(char*));
	lbuf = ptr;
	
	while (1) {
		int i, vlen;
		char *key, *val, *filename, *eptr;
		
		if (!ptr) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post_data(...): bad boundry condition in multipart/form-data");
			return DECLINED;
		}
		
		if ((*(ptr + blen + 1) == '-') && (*(ptr + blen + 1) == '-')) {
			return OK;
		}
		
		lbuf += (blen + 2);
		remaining -= (blen + 2);
		
		eptr = strstr(lbuf, "\r\n\r\n");
		
		if (!eptr) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post_data(...): bad headers in multipart/form-data");
			return DECLINED;
		}
		
		ptr = lbuf;
		
		memset(eptr + 2, 0, 2);
		remaining -= (eptr - lbuf - sizeof(char*));
		lbuf = eptr + 4;
		
		while (*ptr) {
			char *xptr = ap_getword(r->pool, (const char**) &ptr, ' ');
			
			if (!strcmp("Content-Disposition:", xptr)) {
				xptr = strstr(ptr, "name=");
				
				if (!xptr) {
					ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post_data(...): bad `Content-Disposition:' header");
					return DECLINED;
				}
				
				xptr += 6;
				
				for (i = 0; xptr[i] != '"'; i++) {
					;
				}
				
				key = (char*) apr_palloc(r->pool, i + 1);
				
				memcpy(key, xptr, i);
				key[i] = '\0';
				
				xptr = strstr(ptr, "filename=");
				
				if (xptr) {
					char *file_key, *file_val;
					
					xptr += 10;
					
					for (i = 0; xptr[i] != '"'; i++) {
						;
					}
					
					file_val = (char*) apr_palloc(r->pool, i + 1);
					
					memcpy(file_val, xptr, i);
					file_val[i] = '\0';
					
					file_key = apr_psprintf(r->pool, "%s_filename", key);
					
					set_var2(interp, "::pram", file_key, file_val, i);
				}
				
				break;
			}
			
			ptr = strstr(ptr, "\r\n");
			ptr += 2;
		}
		
		ptr = mstrstr(lbuf, boundary, remaining, blen);
		
		vlen = (ptr - lbuf) - sizeof(char*);
		
		if (vlen <= 0) {
			val = (char*) malloc(1);
			val[0] = '\0';
			vlen = 0;
		}
		else {
			val = (char*) malloc(vlen + 1);
			
			memcpy(val, lbuf, vlen);
			val[vlen] = '\0';
		}

		set_var2(interp, "::pram", key, val, vlen);
		
		free(val);
		
		lbuf = ptr;
		remaining -= vlen;
	}
	
	return DECLINED;
}

static int read_post(request_rec *r, Tcl_Interp *interp)
{
	int rc;
	const char *val, *key;
	char *rbuf;
	
	if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
		return rc;
	}
	
	if (ap_should_client_block(r)) {
		char buf[HUGE_STRING_LEN];
		int rsize, len_read, rpos = 0;
		long length = r->remaining;
		
		rbuf = (char*) apr_pcalloc(r->pool, length + 1);
		
//		ap_hard_timeout("read_post", r);
		
		while ((len_read = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
//			ap_reset_timeout(r);
			
			if ((rpos + len_read) > length) {
				rsize = length - rpos;
			}
			else {
				rsize = len_read;
			}
			
			memcpy(rbuf + rpos, buf, rsize);
			rpos += rsize;
		}
		
//		ap_kill_timeout(r);
	}
	
//	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server, 0, "read_post(...): %u, rbuf = %s", getpid(), rbuf);
	
	while (rbuf && *rbuf && (val = ap_getword(r->pool, (const char**) &rbuf, '&'))) {
		key = ap_getword(r->pool, &val, '=');
		
		ap_unescape_url((char*) key);
		ap_unescape_url((char*) val);
		
		if (!key || !val) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post(...): invalid key or value, key = %s, val = %s", key, val);
			break;
		}
		
		set_var(interp, "::pram", key, val);
	}
	
	return OK;
}

static int read_post_init(request_rec *r, Tcl_Interp *interp)
{
	const char *type = apr_table_get(r->headers_in, "Content-Type");
	char *boundary;
	
	if (read_post_ok) {
		read_post_ok = 0;
	}
	else {
		/* already read */
		return OK;
	}
	
	if (!strcmp(type, "application/x-www-form-urlencoded")) {
		return read_post(r, interp);
	}
	else if (strstr(type, "multipart/form-data")) {
		boundary = strstr(type, "boundary=");
		
		if (!boundary) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post_init(...): no boundry in multipart/form-data");
			return DECLINED;
		}
		
		boundary += 9;
		
		return read_post_data(r, interp, boundary);
	}
	else {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "read_post_init(...): unknown, Content-Type: %s", type);
		
		return DECLINED;
	}
}

int cmd_rputs(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char *opt = NULL, *data;
	
	switch (objc) {
	  case 3:
		opt = Tcl_GetString(objv[1]);
		data = Tcl_GetString(objv[2]);
		break;
	  case 2:
		data = Tcl_GetString(objv[1]);
		break;
	  default:
		Tcl_WrongNumArgs(interp, 1, objv, "?-nonewline? string");
		return TCL_ERROR;
	}
	
	if (opt && strcmp(opt, "-nonewline")) {
		Tcl_WrongNumArgs(interp, 1, objv, "?-nonewline? string");
		return TCL_ERROR;
	}
	
	ap_rprintf(_r, "%s%s", data, opt ? "" : "\n");
	
	return TCL_OK;
}

int cmd_rwrite(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char *data = NULL;
	int length;
	
	switch (objc) {
	  case 2:
		data = (char*) Tcl_GetByteArrayFromObj(objv[1], &length);
		break;
	  default:
		Tcl_WrongNumArgs(interp, 1, objv, "data");
		return TCL_ERROR;
	}
	
	ap_rwrite(data, length, _r);
	
	return TCL_OK;
}

int cmd_ap_send_http_header(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *obj;
	
	obj = Tcl_GetVar2Ex(ixx, "content_type", NULL, 0);
	
	if (obj) {
		_r->content_type = Tcl_GetString(obj);
	}
	
	ap_send_http_header(_r);
	
	return TCL_OK;
}

static int set_headers_in(void *data, const char *key, const char *val)
{
	Tcl_Interp *interp = (Tcl_Interp*) data;
	
	set_var(interp, "headers_in", key, val);
	
	return 1;
}

int cmd_r(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "variable");
		return TCL_ERROR;
	}

	if (!strcmp("method_number", Tcl_GetString(objv[1]))) {
		Tcl_SetObjResult(ixx, Tcl_NewIntObj(_r->method_number));
	}
	else if (!strcmp("uri", Tcl_GetString(objv[1]))) {
		Tcl_SetObjResult(ixx, Tcl_NewStringObj(_r->uri, -1));
	}
	else if (!strcmp("headers_in", Tcl_GetString(objv[1]))) {
		apr_table_do(set_headers_in, ixx, _r->headers_in, NULL);
		run_script(ixx, "array names headers_in");
	}	
	
	return TCL_OK;
}

int cmd_r_set(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc < 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "variable ?variables?");
		return TCL_ERROR;
	}
	
	if (!strcmp("content_type", Tcl_GetString(objv[1]))) {
		_r->content_type = Tcl_GetString(objv[2]);
	}
	else if (!strcmp("headers_out", Tcl_GetString(objv[1]))) {
		if (objc != 4) {
			return TCL_ERROR;
		}
		
		apr_table_set(_r->headers_out, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	}
	
	return TCL_OK;
}

int cmd_read_post(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (read_post_init(_r, ixx) != OK) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, _r->server, "cmd_read_post(...): read failed");
		Tcl_AddErrorInfo(ixx, "read failed");
		
		return TCL_ERROR;
	}
	
	return TCL_OK;
}

int cmd_ap_get_server_version(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_get_server_version(), -1));
	
	return TCL_OK;
}

int cmd_ap_create_environment(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char **env;
	int i;
	
	ap_add_cgi_vars(_r);
	ap_add_common_vars(_r);
	
	env = ap_create_environment(_r->pool, _r->subprocess_env);
	
	for (i = 0; env[i]; i++) {
		char *sptr = strchr(env[i], '=');
		
		*sptr = '\0';
		set_var(ixx, "::env", env[i], sptr + 1);
		*sptr = '=';
	}
	
	return TCL_OK;
}

int cmd_abort(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc == 2) {
		Tcl_AddObjErrorInfo(ixx, Tcl_GetString(objv[1]), -1);
	}
	
	return TCL_ERROR;
}

int cmd_ap_internal_redirect(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	ap_internal_redirect(Tcl_GetString(objv[1]), _r);
	
	return TCL_OK;
}

int cmd_random(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewLongObj(random()));
	
	return TCL_OK;
}

int cmd_srandom(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "integer");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &i);
	srandom((unsigned int) i);
	
	return TCL_OK;
}

int cmd_base64_encode(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	uint8_t *data, *enc_data;
	int length;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "data");
		
		return TCL_ERROR;
	}
	
	data = Tcl_GetByteArrayFromObj(objv[1], &length);
	enc_data = buf_to_base64(data, length);
	Tcl_SetObjResult(interp, Tcl_NewStringObj((char*) enc_data, -1));
	
	free(enc_data);
	
	return TCL_OK;
}

int cmd_base64_decode(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	uint8_t *enc_data, *ws_data, *data;
	size_t length;
	Tcl_Obj *obj;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "string");
		
		return TCL_ERROR;
	}
	
	enc_data = (uint8_t*) Tcl_GetString(objv[1]);
	ws_data = base64_remove_whitespace(enc_data, 0);
	data = base64_to_buf(data, &length);
	
	obj = Tcl_NewObj();
	Tcl_SetByteArrayObj(obj, (unsigned char*) data, length);
	
	free(ws_data);
	free(data);
	
	return TCL_OK;
}

int cmd_ap_allow_options(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_allow_options(_r)));
	
	return TCL_OK;
}

int cmd_ap_allow_overrides(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_allow_overrides(_r)));
	
	return TCL_OK;
}

int cmd_ap_default_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_default_type(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_document_root(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_document_root(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_get_remote_host(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "type");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &i);
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_get_remote_host(_r->connection, _r->per_dir_config, i), -1));
	
	return TCL_OK;
}

int cmd_ap_get_remote_logname(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_get_remote_logname(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_construct_url(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_construct_url(_r->pool, Tcl_GetString(objv[1]), _r), -1));
	
	return TCL_OK;
}

int cmd_ap_get_server_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_get_server_name(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_get_server_port(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	/* int should suffice since ports are usually unsigned short */
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_get_server_port(_r)));
	
	return TCL_OK;
}

int cmd_ap_get_limit_req_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	/* ap_get_limit_req_body returns an unsigned long, its possible it could overflow in TCL
	   as it doesn't appear to have any unsigned support... it might be possible to assign it
	   to a double?
	*/
	Tcl_SetObjResult(ixx, Tcl_NewLongObj(ap_get_limit_req_body(_r)));
	
	return TCL_OK;
}

int cmd_ap_get_limit_xml_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_get_limit_xml_body(_r)));
	
	return TCL_OK;
}

int cmd_ap_custom_response(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i;
	
	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "status string");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &i);
	ap_custom_response(_r, i, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

int cmd_ap_exists_config_define(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, "name");
		
		return TCL_ERROR;
	}
	
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_exists_config_define(Tcl_GetString(objv[1]))));
	
	return TCL_OK;
}

int cmd_ap_auth_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_auth_type(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_auth_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewStringObj(ap_auth_name(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_satisfies(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(ixx, Tcl_NewIntObj(ap_satisfies(_r)));
	
	return TCL_OK;
}

int cmd_ap_requires(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i;
	const apr_array_header_t *a = ap_requires(_r);
	require_line *ra = (require_line*) a->elts;
	Tcl_Obj *obj = Tcl_NewObj();
	
	for (i = 0; i < a->nelts; i++) {
		Tcl_Obj *xobj = Tcl_NewObj();
		
		Tcl_ListObjAppendElement(ixx, xobj, Tcl_NewIntObj(ra[i].method_mask));
		Tcl_ListObjAppendElement(ixx, xobj, Tcl_NewStringObj(ra[i].requirement, -1));
		
		Tcl_ListObjAppendElement(ixx, obj, xobj);
	}
	
	Tcl_SetObjResult(ixx, obj);
	
	return TCL_OK;
}
