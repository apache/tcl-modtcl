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
extern apr_pool_t			*_pconf;
extern char					*current_namespace;
extern int					read_post_ok;

static int sorted = 0, r_size = 0, connection_size = 0, server_size = 0;

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
	char *lbuf, *ptr, *nm_var = apr_psprintf(r->pool, "%s::pram", r->filename);
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
					
					set_varb(interp, nm_var, file_key, file_val, i);
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

		set_varb(interp, nm_var, key, val, vlen);
		
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
	char *nm_var = apr_psprintf(r->pool, "%s::pram", r->filename);
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
		
		set_var(interp, nm_var, (char*) key, (char*) val);
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

static Tcl_Obj* r_the_request(void)
{
	return Tcl_NewStringObj(_r->the_request, -1);
}

static Tcl_Obj* r_assbackwards(void)
{
	return Tcl_NewIntObj(_r->assbackwards);
}

static Tcl_Obj* r_proxyreq(void)
{
	return Tcl_NewIntObj(_r->proxyreq);
}

static Tcl_Obj* r_header_only(void)
{
	return Tcl_NewIntObj(_r->header_only);
}

static Tcl_Obj* r_protocol(void)
{
	return Tcl_NewStringObj(_r->protocol, -1);
}

static Tcl_Obj* r_proto_num(void)
{
	return Tcl_NewIntObj(_r->proto_num);
}

static Tcl_Obj* r_hostname(void)
{
	return Tcl_NewStringObj(_r->hostname, -1);
}

static Tcl_Obj* r_request_time(void)
{
	return Tcl_NewLongObj(_r->request_time);
}

static Tcl_Obj* r_status_line(void)
{
	return Tcl_NewStringObj(_r->status_line, -1);
}

static Tcl_Obj* r_status(void)
{
	return Tcl_NewIntObj(_r->status);
}

static Tcl_Obj* r_method(void)
{
	return Tcl_NewStringObj(_r->method, -1);
}

static Tcl_Obj* r_method_number(void)
{
	return Tcl_NewIntObj(_r->method_number);
}

static Tcl_Obj* r_allowed(void)
{
	return Tcl_NewIntObj(_r->allowed);
}

/* hasn't been implemented ? */
static Tcl_Obj* r_allowed_xmethods(void)
{
	return Tcl_NewStringObj("", -1);
}

static Tcl_Obj* r_allowed_methods(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	char **method_list = (char**) _r->allowed_methods->method_list->elts;
	
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(_r->allowed_methods->method_mask));
	
	for (i = 0; i < _r->allowed_methods->method_list->nelts; i++) {
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(method_list[i], -1));
	}
	
	return obj;
}

static Tcl_Obj* r_sent_bodyct(void)
{
	return Tcl_NewIntObj(_r->sent_bodyct);
}

static Tcl_Obj* r_bytes_sent(void)
{
	return Tcl_NewIntObj(_r->bytes_sent);
}

static Tcl_Obj* r_mtime(void)
{
	return Tcl_NewLongObj(_r->mtime);
}

static Tcl_Obj* r_chunked(void)
{
	return Tcl_NewIntObj(_r->chunked);
}

static Tcl_Obj* r_boundary(void)
{
	return Tcl_NewStringObj(_r->boundary, -1);
}

static Tcl_Obj* r_range(void)
{
	return Tcl_NewStringObj(_r->range, -1);
}

static Tcl_Obj* r_clength(void)
{
	return Tcl_NewLongObj(_r->clength);
}

static Tcl_Obj* r_remaining(void)
{
	return Tcl_NewLongObj(_r->remaining);
}

static Tcl_Obj* r_read_length(void)
{
	return Tcl_NewLongObj(_r->read_length);
}

static Tcl_Obj* r_read_body(void)
{
	return Tcl_NewIntObj(_r->read_body);
}

static Tcl_Obj* r_read_chunked(void)
{
	return Tcl_NewIntObj(_r->read_chunked);
}

static Tcl_Obj* r_expecting_100(void)
{
	return Tcl_NewIntObj(_r->expecting_100);
}

static Tcl_Obj* r_headers_in(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->headers_in);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "headers_in", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

static Tcl_Obj* r_headers_out(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->headers_out);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "headers_out", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

static Tcl_Obj* r_err_headers_out(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->err_headers_out);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "err_headers_out", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

/* ap_create_environment() sets ::env */
static Tcl_Obj* r_subprocess_env(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->subprocess_env);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "subprocess_env", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

static Tcl_Obj* r_notes(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->notes);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "notes", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

static Tcl_Obj* r_content_type(void)
{
	return Tcl_NewStringObj(_r->content_type, -1);
}

static Tcl_Obj* r_handler(void)
{
	return Tcl_NewStringObj(_r->handler, -1);
}

static Tcl_Obj* r_content_encoding(void)
{
	return Tcl_NewStringObj(_r->content_encoding, -1);
}

static Tcl_Obj* r_content_languages(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	char **content_languages = (char**) _r->content_languages->elts;

	for (i = 0; i < _r->content_languages->nelts; i++) {
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(content_languages[i], -1));
	}
	
	return obj;
}

static Tcl_Obj* r_vlist_validator(void)
{
	return Tcl_NewStringObj(_r->vlist_validator, -1);
}

static Tcl_Obj* r_user(void)
{
	return Tcl_NewStringObj(_r->user, -1);
}

static Tcl_Obj* r_ap_auth_type(void)
{
	return Tcl_NewStringObj(_r->ap_auth_type, -1);
}

static Tcl_Obj* r_no_cache(void)
{
	return Tcl_NewIntObj(_r->no_cache);
}

static Tcl_Obj* r_no_local_copy(void)
{
	return Tcl_NewIntObj(_r->no_local_copy);
}

static Tcl_Obj* r_unparsed_uri(void)
{
	return Tcl_NewStringObj(_r->unparsed_uri, -1);
}

static Tcl_Obj* r_uri(void)
{
	return Tcl_NewStringObj(_r->uri, -1);
}

static Tcl_Obj* r_filename(void)
{
	return Tcl_NewStringObj(_r->filename, -1);
}

static Tcl_Obj* r_path_info(void)
{
	return Tcl_NewStringObj(_r->path_info, -1);
}

static Tcl_Obj* r_args(void)
{
	return Tcl_NewStringObj(_r->args, -1);
}

static Tcl_Obj* r_parsed_uri(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.scheme, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.hostinfo, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.user, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.password, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.hostname, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.port_str, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.path, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.query, -1));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->parsed_uri.fragment, -1));
	
	/* is the rest important? */
	
	return obj;
}

/* variables in r->connection */

static Tcl_Obj* r_connection_remote_ip(void)
{
	return Tcl_NewStringObj(_r->connection->remote_ip, -1);
}

static Tcl_Obj* r_connection_remote_host(void)
{
	return Tcl_NewStringObj(_r->connection->remote_host, -1);
}

static Tcl_Obj* r_connection_remote_logname(void)
{
	return Tcl_NewStringObj(_r->connection->remote_logname, -1);
}

static Tcl_Obj* r_connection_aborted(void)
{
	return Tcl_NewIntObj(_r->connection->aborted);
}

static Tcl_Obj* r_connection_keepalive(void)
{
	return Tcl_NewIntObj(_r->connection->keepalive);
}

static Tcl_Obj* r_connection_double_reverse(void)
{
	return Tcl_NewIntObj(_r->connection->double_reverse);
}

static Tcl_Obj* r_connection_keepalives(void)
{
	return Tcl_NewIntObj(_r->connection->keepalives);
}

static Tcl_Obj* r_connection_local_ip(void)
{
	return Tcl_NewStringObj(_r->connection->local_ip, -1);
}

static Tcl_Obj* r_connection_local_host(void)
{
	return Tcl_NewStringObj(_r->connection->local_host, -1);
}

static Tcl_Obj* r_connection_id(void)
{
	return Tcl_NewLongObj(_r->connection->id);
}

static Tcl_Obj* r_connection_notes(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	const apr_array_header_t *ha = apr_table_elts(_r->connection->notes);
	apr_table_entry_t *hte = (apr_table_entry_t*) ha->elts;

	for (i = 0; i < ha->nelts; i++) {
		Tcl_SetVar2Ex(interp, "connection_notes", hte[i].key, Tcl_NewStringObj(hte[i].val, -1), 0);
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(hte[i].key, -1));
	}
	
	return obj;
}

static Tcl_Obj* r_server_defn_name(void)
{
	return Tcl_NewStringObj(_r->server->defn_name, -1);
}

static Tcl_Obj* r_server_defn_line_number(void)
{
	return Tcl_NewIntObj(_r->server->defn_line_number);
}

static Tcl_Obj* r_server_server_admin(void)
{
	return Tcl_NewStringObj(_r->server->server_admin, -1);
}

static Tcl_Obj* r_server_server_hostname(void)
{
	return Tcl_NewStringObj(_r->server->server_hostname, -1);
}

static Tcl_Obj* r_server_port(void)
{
	return Tcl_NewIntObj(_r->server->port);
}

static Tcl_Obj* r_server_error_fname(void)
{
	return Tcl_NewStringObj(_r->server->error_fname, -1);
}

static Tcl_Obj* r_server_loglevel(void)
{
	return Tcl_NewIntObj(_r->server->loglevel);
}

static Tcl_Obj* r_server_is_virtual(void)
{
	return Tcl_NewIntObj(_r->server->is_virtual);
}

static Tcl_Obj* r_server_addrs(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(_r->server->addrs->host_port));
	Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(_r->server->addrs->virthost, -1));
	
	return obj;
}

static Tcl_Obj* r_server_timeout(void)
{
	return Tcl_NewIntObj(_r->server->timeout);
}

static Tcl_Obj* r_server_keep_alive_timeout(void)
{
	return Tcl_NewIntObj(_r->server->keep_alive_timeout);
}

static Tcl_Obj* r_server_keep_alive_max(void)
{
	return Tcl_NewIntObj(_r->server->keep_alive_max);
}

static Tcl_Obj* r_server_keep_alive(void)
{
	return Tcl_NewIntObj(_r->server->keep_alive);
}

static Tcl_Obj* r_server_path(void)
{
	return Tcl_NewStringObj(_r->server->path, -1);
}

static Tcl_Obj* r_server_names(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	char **a = (char**) _r->server->names->elts;
	
	for (i = 0; i < _r->server->names->nelts; i++) {
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(a[i], -1));
	}
	
	return obj;
}

static Tcl_Obj* r_server_wild_names(void)
{
	Tcl_Obj *obj = Tcl_NewObj();
	int i;
	char **a = (char**) _r->server->wild_names->elts;
	
	for (i = 0; i < _r->server->wild_names->nelts; i++) {
		Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(a[i], -1));
	}
	
	return obj;
}

static Tcl_Obj* r_server_limit_req_line(void)
{
	return Tcl_NewIntObj(_r->server->limit_req_line);
}

static Tcl_Obj* r_server_limit_req_fieldsize(void)
{
	return Tcl_NewIntObj(_r->server->limit_req_fieldsize);
}

static Tcl_Obj* r_server_limit_req_fields(void)
{
	return Tcl_NewIntObj(_r->server->limit_req_fields);
}

/* sets */
static int r_set_the_request(int objc, Tcl_Obj *CONST objv[])
{
	_r->the_request = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_assbackwards(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->assbackwards));
	
	return TCL_OK;
}

static int r_set_proxyreq(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->proxyreq));
	
	return TCL_OK;
}

static int r_set_header_only(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->header_only));
	
	return TCL_OK;
}

static int r_set_protocol(int objc, Tcl_Obj *CONST objv[])
{
	_r->protocol = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_proto_num(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->proto_num));
	
	return TCL_OK;
}

static int r_set_allowed(int objc, Tcl_Obj *CONST objv[])
{
#if TCL_MAJOR_VERSION > 7 && TCL_MINOR_VERSION > 3
	Tcl_GetWideIntFromObj(interp, objv[2], &(_r->allowed));
#endif

	return TCL_OK;
}

/* ? */
static int r_set_allowed_xmethods(int objc, Tcl_Obj *CONST objv[])
{	
	return TCL_OK;
}

static int r_set_allowed_methods(int objc, Tcl_Obj *CONST objv[])
{
	int xxobjc;
	Tcl_Obj **xxobjv;
	int i;
	
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "method_mask method_list");
		return TCL_ERROR;
	}
#if TCL_MAJOR_VERSION > 7 && TCL_MINOR_VERSION > 3
	Tcl_GetWideIntFromObj(interp, objv[2], &(_r->allowed_methods->method_mask));
	
	if (Tcl_ListObjGetElements(interp, objv[3], &xxobjc, &xxobjv) == TCL_ERROR) {
		return TCL_ERROR;
	}
	
	_r->allowed_methods->method_list = (apr_array_header_t*) apr_array_make(_r->allowed_methods->method_list->pool, xxobjc, sizeof(char*));
	
	for (i = 0; i < xxobjc; i++) {
		char *xx = (char*) apr_array_push(_r->allowed_methods->method_list);
		
		xx = apr_pstrdup(_r->allowed_methods->method_list->pool, Tcl_GetString(xxobjv[i]));
	}
#endif
	return TCL_OK;
}

static int r_set_headers_out(int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "header_name header");
		return TCL_ERROR;
	}
	
	apr_table_set(_r->headers_out, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	
	return TCL_OK;
}

static int r_set_err_headers_out(int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "header_name header");
		return TCL_ERROR;
	}
	
	apr_table_set(_r->err_headers_out, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	
	return TCL_OK;
}

static int r_set_filename(int objc, Tcl_Obj *CONST objv[])
{
	_r->filename = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_subprocess_env(int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "variable_name variable");
		return TCL_ERROR;
	}
	
	apr_table_set(_r->subprocess_env, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	
	return TCL_OK;
}

static int r_set_notes(int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "note_name note");
		return TCL_ERROR;
	}
	
	apr_table_set(_r->notes, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	
	return TCL_OK;
}

static int r_set_content_type(int objc, Tcl_Obj *CONST objv[])
{
	_r->content_type = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_content_encoding(int objc, Tcl_Obj *CONST objv[])
{
	_r->content_encoding = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_content_languages(int objc, Tcl_Obj *CONST objv[])
{
	int xxobjc;
	Tcl_Obj **xxobjv;
	int i;
	
	if (Tcl_ListObjGetElements(interp, objv[2], &xxobjc, &xxobjv) == TCL_ERROR) {
		return TCL_ERROR;
	}
	
	_r->content_languages = apr_array_make(_r->content_languages->pool, xxobjc, sizeof(char*));
	
	for (i = 0; i < xxobjc; i++) {
		char *xx = apr_array_push(_r->content_languages);
		
		xx = apr_pstrdup(_r->content_languages->pool, Tcl_GetString(xxobjv[i]));
	}
	
	return TCL_OK;
}

static int r_set_vlist_validator(int objc, Tcl_Obj *CONST objv[])
{
	_r->vlist_validator = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_user(int objc, Tcl_Obj *CONST objv[])
{
	_r->user = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_ap_auth_type(int objc, Tcl_Obj *CONST objv[])
{
	_r->ap_auth_type = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_no_cache(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->no_cache));
	
	return TCL_OK;
}

static int r_set_no_local_copy(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_GetIntFromObj(interp, objv[2], &(_r->no_local_copy));
	
	return TCL_OK;
}

static int r_set_unparsed_uri(int objc, Tcl_Obj *CONST objv[])
{
	_r->unparsed_uri = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_uri(int objc, Tcl_Obj *CONST objv[])
{
	_r->uri = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_path_info(int objc, Tcl_Obj *CONST objv[])
{
	_r->path_info = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_args(int objc, Tcl_Obj *CONST objv[])
{
	_r->args = apr_pstrdup(_r->pool, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

static int r_set_parsed_uri(int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(apr_uri_parse(_r->pool, Tcl_GetString(objv[2]), &(_r->parsed_uri))));
		
	return TCL_OK;
}

static int r_set_connection_notes(int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "note_name note");
		return TCL_ERROR;
	}
	
	apr_table_set(_r->connection->notes, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	
	return TCL_OK;
}


typedef Tcl_Obj* (*fy_t)(void);
typedef int (*fx_t)(int objc, Tcl_Obj *CONST objv[]);

typedef struct {
	char	*var;
	fy_t	rd_func;
	fx_t	wr_func;
} r_table;

static int r_find(const void *x, const void *y)
{
	return strcmp(((r_table*) x)->var, ((r_table*) y)->var);
}

r_table r_tbl[] = {
	{ "allowed",			r_allowed,			r_set_allowed			},
	{ "allowed_methods",	r_allowed_methods,	r_set_allowed_methods	},
	{ "allowed_xmethods",	r_allowed_xmethods,	r_set_allowed_xmethods	},
	{ "ap_auth_type",		r_ap_auth_type,		r_set_ap_auth_type		},
	{ "args",				r_args,				r_set_args				},
	{ "assbackwards",		r_assbackwards,		r_set_assbackwards		},
	{ "boundary",			r_boundary,			NULL					},
	{ "bytes_sent",			r_bytes_sent,		NULL					},
	{ "chunked",			r_chunked,			NULL					},
	{ "clength",			r_clength,			NULL					},
	{ "content_encoding",	r_content_encoding,	r_set_content_encoding	},
/*	{ "content_languages",	r_content_languages,r_set_content_languages	}, this is fuct up, and I have no idea why */
	{ "content_type",		r_content_type,		r_set_content_type		},
	{ "err_headers_out",	r_err_headers_out,	r_set_err_headers_out	},
	{ "expecting_100",		r_expecting_100,	NULL					},
	{ "filename",			r_filename,			r_set_filename			},
	{ "handler",			r_handler,			NULL					},
	{ "headers_in",			r_headers_in,		NULL					},
	{ "headers_out",		r_headers_out,		r_set_headers_out		},
	{ "header_only",		r_header_only,		r_set_header_only		},
	{ "hostname",			r_hostname,			NULL					},
	{ "method",				r_method,			NULL					},
	{ "method_number",		r_method_number,	NULL					},
	{ "mtime",				r_mtime,			NULL					},
	{ "notes",				r_notes,			r_set_notes				},
	{ "no_cache",			r_no_cache,			r_set_no_cache			},
	{ "no_local_copy",		r_no_local_copy,	r_set_no_local_copy		},
	{ "parsed_uri",			r_parsed_uri,		r_set_parsed_uri		},
	{ "path_info",			r_path_info,		r_set_path_info			},
	{ "protocol",			r_protocol,			r_set_protocol			},
	{ "proto_num",			r_proto_num,		r_set_proto_num			},
	{ "proxyreq",			r_proxyreq,			r_set_proxyreq			},
	{ "range",				r_range,			NULL					},
	{ "read_body",			r_read_body,		NULL					},
	{ "read_chunked",		r_read_chunked,		NULL					},
	{ "read_length",		r_read_length,		NULL					},
	{ "remaining",			r_remaining,		NULL					},
	{ "request_time",		r_request_time,		NULL					},
	{ "sent_bodyct",		r_sent_bodyct,		NULL					},
	{ "status",				r_status,			NULL					},
	{ "status_line",		r_status_line,		NULL					},
	{ "subprocess_env",		r_subprocess_env,	r_set_subprocess_env	},
	{ "the_request",		r_the_request,		r_set_the_request		},
	{ "unparsed_uri",		r_unparsed_uri,		r_set_unparsed_uri		},
	{ "uri",				r_uri,				r_set_uri				},
	{ "user",				r_user,				r_set_user				},
	{ "vlist_validator",	r_vlist_validator,	r_set_vlist_validator	},
	{ NULL,					NULL,				NULL					}
};

r_table r_connection_tbl[] = {
	{ "remote_ip",			r_connection_remote_ip,			NULL					},
	{ "remote_host",		r_connection_remote_host,		NULL					},
	{ "remote_logname",		r_connection_remote_logname,	NULL					},
	{ "aborted",			r_connection_aborted,			NULL					},
	{ "keepalive",			r_connection_keepalive,			NULL					},
	{ "doublereverse",		r_connection_double_reverse,	NULL					},
	{ "keepalives",			r_connection_keepalives,		NULL					},
	{ "local_ip",			r_connection_local_ip,			NULL					},
	{ "local_host",			r_connection_local_host,		NULL					},
	{ "id",					r_connection_id,				NULL					},
	{ "notes",				r_connection_notes,				r_set_connection_notes	},
	{ NULL,					NULL,							NULL					}
};

r_table r_server_tbl[] = {
	{ "defn_name",				r_server_defn_name,				NULL	},
	{ "defn_line_number",		r_server_defn_line_number,		NULL	},
	{ "server_admin",			r_server_server_admin,			NULL	},
	{ "server_hostname",		r_server_server_hostname,		NULL	},
	{ "port",					r_server_port,					NULL	},
	{ "error_fname",			r_server_error_fname,			NULL	},
	{ "loglevel",				r_server_loglevel,				NULL	},
	{ "is_virtual",				r_server_is_virtual,			NULL	},
	{ "addrs",					r_server_addrs,					NULL	},
	{ "timeout",				r_server_timeout,				NULL	},
	{ "keep_alive_timeout",		r_server_keep_alive_timeout,	NULL	},
	{ "keep_alive_max",			r_server_keep_alive_max,		NULL	},
	{ "keep_alive",				r_server_keep_alive,			NULL	},
	{ "path",					r_server_path,					NULL	},
	{ "names",					r_server_names,					NULL	},
	{ "wild_names",				r_server_wild_names,			NULL	},
	{ "limit_req_line",			r_server_limit_req_line,		NULL	},
	{ "limit_req_fieldsize",	r_server_limit_req_fieldsize,	NULL	},
	{ "limit_req_fields",		r_server_limit_req_fields,		NULL	},
	{ NULL,						NULL,							NULL	}
};

int cmd_r(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char *xx = NULL, *yy = NULL;
	r_table *r_table_ptr, key;
	
	switch (objc) {
	  case 3: yy = Tcl_GetString(objv[2]);
	  case 2: xx = Tcl_GetString(objv[1]);	break;
	  default:
		Tcl_WrongNumArgs(interp, 1, objv, "variable");
		return TCL_ERROR;
	}

	if (!sorted) {
		for (; r_tbl[r_size].var != NULL; r_size++);
		for (; r_connection_tbl[connection_size].var != NULL; connection_size++);
		for (; r_server_tbl[server_size].var != NULL; server_size++);
		
		qsort(r_tbl, r_size, sizeof(r_table), r_find);
		qsort(r_connection_tbl, connection_size, sizeof(r_table), r_find);
		qsort(r_server_tbl, server_size, sizeof(r_table), r_find);
		
		sorted = 1;
	}
	
	if (!strcmp(xx, "server")) {
		if (!yy) {
			Tcl_WrongNumArgs(interp, 2, objv, "variable");
			return TCL_ERROR;
		}
		
		key.var = yy;
		r_table_ptr = (r_table*) bsearch(&key, r_server_tbl, server_size, sizeof(r_table), r_find);
	}
	else if (!strcmp(xx, "connection")) {
		if (!yy) {
			Tcl_WrongNumArgs(interp, 2, objv, "variable");
			return TCL_ERROR;
		}
		
		key.var = yy;
		r_table_ptr = (r_table*) bsearch(&key, r_connection_tbl, connection_size, sizeof(r_table), r_find);
	}
	else {
		key.var = xx;
		r_table_ptr = (r_table*) bsearch(&key, r_tbl, r_size, sizeof(r_table), r_find);
	}
	
	if (!r_table_ptr) {
		char *p;
		
		asprintf(&p, "%s is not known in structure.", xx);
		Tcl_AddObjErrorInfo(interp, p, -1);
		
		free(p);
		
		return TCL_ERROR;
	}
	
	Tcl_SetObjResult(interp, r_table_ptr->rd_func());
	
	return TCL_OK;
}

int cmd_r_set(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char *xx, *yy;
	r_table *r_table_ptr, key;
	
	switch (objc) {
	  default:
	  case 3: yy = Tcl_GetString(objv[2]);
	  case 2: xx = Tcl_GetString(objv[1]);	break;
	  case 1:
		Tcl_WrongNumArgs(interp, 1, objv, "variable");
		return TCL_ERROR;
	}
	
	if (!sorted) {
		for (; r_tbl[r_size].var != NULL; r_size++);
		for (; r_connection_tbl[connection_size].var != NULL; connection_size++);
		for (; r_server_tbl[server_size].var != NULL; server_size++);
		
		qsort(r_tbl, r_size, sizeof(r_table), r_find);
		qsort(r_connection_tbl, connection_size, sizeof(r_table), r_find);
		qsort(r_server_tbl, server_size, sizeof(r_table), r_find);
		
		sorted = 1;
	}
	
	if (!strcmp(xx, "server")) {
		if (!yy) {
			Tcl_WrongNumArgs(interp, 2, objv, "variable ?variables?");
			return TCL_ERROR;
		}
		
		key.var = yy;
		r_table_ptr = (r_table*) bsearch(&key, r_server_tbl, server_size, sizeof(r_table), r_find);
	}
	else if (!strcmp(xx, "connection")) {
		if (!yy) {
			Tcl_WrongNumArgs(interp, 2, objv, "variable ?variables?");
			return TCL_ERROR;
		}
		
		key.var = yy;
		r_table_ptr = (r_table*) bsearch(&key, r_connection_tbl, connection_size, sizeof(r_table), r_find);
	}
	else {
		key.var = xx;
		r_table_ptr = (r_table*) bsearch(&key, r_tbl, r_size, sizeof(r_table), r_find);
	}
	
	if (!r_table_ptr) {
		char *p;
		
		asprintf(&p, "%s is not known in structure.", xx);
		Tcl_AddObjErrorInfo(interp, p, -1);
		
		free(p);
		
		return TCL_ERROR;
	}
	
	if (r_table_ptr->wr_func) {
		return r_table_ptr->wr_func(objc, objv);
	}
	else {
		Tcl_AddObjErrorInfo(interp, "this variable is not writable", -1);
		return TCL_ERROR;
	}
}

int cmd_read_post(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (read_post_init(_r, interp) != OK) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, _r->server, "cmd_read_post(...): read failed");
		Tcl_AddErrorInfo(interp, "read failed");
		
		return TCL_ERROR;
	}
	
	return TCL_OK;
}

int cmd_abort(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc == 2) {
		Tcl_AddObjErrorInfo(interp, Tcl_GetString(objv[1]), -1);
	}
	
	return TCL_ERROR;
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

/* http_core.h */

int cmd_ap_allow_options(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_allow_options(_r)));
	
	return TCL_OK;
}

int cmd_ap_allow_overrides(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_allow_overrides(_r)));
	
	return TCL_OK;
}

int cmd_ap_default_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_default_type(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_document_root(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_document_root(_r), -1));
	
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
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_remote_host(_r->connection, _r->per_dir_config, i, NULL), -1));
	
	return TCL_OK;
}

int cmd_ap_get_remote_logname(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_remote_logname(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_construct_url(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_construct_url(_r->pool, Tcl_GetString(objv[1]), _r), -1));
	
	return TCL_OK;
}

int cmd_ap_get_server_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_server_name(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_get_server_port(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	/* int should suffice since ports are usually unsigned short */
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_get_server_port(_r)));
	
	return TCL_OK;
}

int cmd_ap_get_limit_req_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	/* ap_get_limit_req_body returns an unsigned long, its possible it could overflow in TCL
	   as it doesn't appear to have any unsigned support... it might be possible to assign it
	   to a double?
	*/
	Tcl_SetObjResult(interp, Tcl_NewLongObj(ap_get_limit_req_body(_r)));
	
	return TCL_OK;
}

int cmd_ap_get_limit_xml_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_get_limit_xml_body(_r)));
	
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
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_exists_config_define(Tcl_GetString(objv[1]))));
	
	return TCL_OK;
}

int cmd_ap_auth_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_auth_type(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_auth_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_auth_name(_r), -1));
	
	return TCL_OK;
}

int cmd_ap_satisfies(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_satisfies(_r)));
	
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
		
		Tcl_ListObjAppendElement(interp, xobj, Tcl_NewIntObj(ra[i].method_mask));
		Tcl_ListObjAppendElement(interp, xobj, Tcl_NewStringObj(ra[i].requirement, -1));
		
		Tcl_ListObjAppendElement(interp, obj, xobj);
	}
	
	Tcl_SetObjResult(interp, obj);
	
	return TCL_OK;
}

/* http_log.h */

int cmd_ap_log_error(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i, j;
	
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 1, objv, "level status string");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &i);
	Tcl_GetIntFromObj(interp, objv[2], &j);
	
	ap_log_error(APLOG_MARK, i, j, _r->server, Tcl_GetString(objv[3]));
	
	return TCL_OK;
}

/* http_protocol.h */

int cmd_ap_send_http_header(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
/*
	Tcl_Obj *obj;
	
	obj = Tcl_GetVar2Ex(interp, "content_type", NULL, 0);
	
	if (obj) {
		_r->content_type = Tcl_GetString(obj);
	}
	
	ap_send_http_header(_r);
*/
	
	return TCL_OK;
}

int cmd_ap_send_http_trace(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_send_http_trace(_r)));
	
	return TCL_OK;
}

int cmd_ap_send_http_options(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_send_http_options(_r)));
	
	return TCL_OK;
}

int cmd_ap_finalize_request_protocol(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_finalize_request_protocol(_r);
	
	return TCL_OK;
}

int cmd_ap_send_error_response(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int recursive_error;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "recursive_error");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &recursive_error);
	
	ap_send_error_response(_r, recursive_error);
	
	return TCL_OK;
}

int cmd_ap_set_content_length(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	apr_off_t length;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "length");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], (int*) &length);
	
	ap_set_content_length(_r, length);
	
	return TCL_OK;
}

int cmd_ap_set_keepalive(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_set_keepalive(_r)));
	
	return TCL_OK;
}

int cmd_ap_rationalize_mtime(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	apr_time_t mtime;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "mtime");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], (int*) &mtime);
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_rationalize_mtime(_r, mtime)));
	
	return TCL_OK;
}

int cmd_ap_make_etag(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int i;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "force_weak");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &i);
	
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_make_etag(_r, i), -1));
	
	return TCL_OK;
}

int cmd_ap_set_etag(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_set_etag(_r);
	
	return TCL_OK;
}

int cmd_ap_set_last_modified(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_set_last_modified(_r);
	
	return TCL_OK;
}

int cmd_ap_meets_conditions(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_meets_conditions(_r)));
	
	return TCL_OK;
}

/* ... skipping method stuff ... */

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

int cmd_ap_rflush(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_rflush(_r);
	
	return TCL_OK;
}

/* skip ap_index_of_response() */

int cmd_ap_get_status_line(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int status;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "status");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &status);
	
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_status_line(status), -1));
	
	return TCL_OK;
}

int cmd_ap_setup_client_block(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int read_policy;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "read_policy");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &read_policy);
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_setup_client_block(_r, read_policy)));
	
	return TCL_OK;
}

int cmd_ap_get_client_block(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int bufsiz;
	char *buffer;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "bufsiz");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &bufsiz);
	
	buffer = malloc(bufsiz);
	
	bufsiz = ap_get_client_block(_r, buffer, bufsiz);
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(bufsiz));
	
	if (bufsiz > 0) {
		Tcl_SetVar2Ex(interp, "R", NULL, Tcl_NewByteArrayObj(buffer, bufsiz), TCL_LEAVE_ERR_MSG);
	}
	
	free(buffer);
	
	return TCL_OK;
}

int cmd_ap_discard_request_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_discard_request_body(_r)));
	
	return TCL_OK;
}

int cmd_ap_note_auth_failure(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_note_auth_failure(_r);
	
	return TCL_OK;
}

int cmd_ap_note_basic_auth_failure(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_note_basic_auth_failure(_r);
	
	return TCL_OK;
}

int cmd_ap_note_digest_auth_failure(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{	
	ap_note_digest_auth_failure(_r);
	
	return TCL_OK;
}

int cmd_ap_get_basic_auth_pw(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	const char *pw;
	int xx;
	
	xx = ap_get_basic_auth_pw(_r, &pw);
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(xx));

	if (xx != 0) {
		Tcl_SetVar2Ex(interp, "R", NULL, Tcl_NewStringObj(pw, -1), TCL_LEAVE_ERR_MSG);
	}
	
	return TCL_OK;
}

/* skip ap_set_sub_req_protocol() and ap_finalize_sub_req_protocol() */

int cmd_ap_parse_uri(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	ap_parse_uri(_r, Tcl_GetString(objv[1]));
	
	return TCL_OK;
}

/* skip ap_getline(), not sure what it does yet */

int cmd_ap_method_number_of(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "method");
		
		return TCL_ERROR;
	}
	
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_method_number_of(Tcl_GetString(objv[1]))));
	
	return TCL_OK;
}

int cmd_ap_method_name_of(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int methnum;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "method");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &methnum);
	
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_method_name_of(_r->pool, methnum), -1));
	
	return TCL_OK;
}

/* http_request.h */
 
/* skip sub requests ... */

int cmd_ap_internal_redirect(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	ap_internal_redirect(Tcl_GetString(objv[1]), _r);
	
	return TCL_OK;
}

int cmd_ap_internal_redirect_handler(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "uri");
		
		return TCL_ERROR;
	}
	
	ap_internal_redirect_handler(Tcl_GetString(objv[1]), _r);
	
	return TCL_OK;
}

int cmd_ap_some_auth_required(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewIntObj(ap_some_auth_required(_r)));
	
	return TCL_OK;
}

/* skip ap_is_initial_req() */

int cmd_ap_update_mtime(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int dependency_mtime;
	
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "dependency_mtime");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &dependency_mtime);
	
	ap_update_mtime(_r, dependency_mtime);
	
	return TCL_OK;
}

int cmd_ap_allow_methods(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	int reset;
	
	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "reset methods");
		
		return TCL_ERROR;
	}
	
	Tcl_GetIntFromObj(interp, objv[1], &reset);
	
	ap_allow_methods(_r, reset, Tcl_GetString(objv[2]));
	
	return TCL_OK;
}

/* httpd.h */

int cmd_ap_get_server_version(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_server_version(), -1));
	
	return TCL_OK;
}

int cmd_ap_add_version_component(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "component");
		
		return TCL_ERROR;
	}
	
	ap_add_version_component(_pconf, Tcl_GetString(objv[1]));
	
	return TCL_OK;
}

int cmd_ap_get_server_built(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj(ap_get_server_built(), -1));
	
	return TCL_OK;
}

/* util_script.h */

int cmd_ap_create_environment(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[])
{
	char **env, *nm_env;
	int i;
	
	asprintf(&nm_env, "::%s::env", _r->filename);
	
	ap_add_cgi_vars(_r);
	ap_add_common_vars(_r);
	
	env = ap_create_environment(_r->pool, _r->subprocess_env);
	
	for (i = 0; env[i]; i++) {
		char *sptr = strchr(env[i], '=');
		
		*sptr = '\0';
		set_var(interp, nm_env, env[i], sptr + 1);
		*sptr = '=';
	}
	
	free(nm_env);
	
	return TCL_OK;
}
