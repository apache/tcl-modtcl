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

#ifndef __MOD_TCL_H__
#define __MOD_TCL_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif /* HAVE_INTTYPES_H */

#ifdef HAVE_INT_TYPES_H
#include <int_types.h>
#endif /* HAVE_INT_TYPES_H */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "ap_config_auto.h"

#ifndef HAVE_TCL_H
#error "uhh, no tcl.h found"
#endif /* HAVE_TCL_H */

#include <tcl.h>

#ifndef HAVE_ASPRINTF
int int_vasprintf(char **result, const char *format, va_list *args);
int vasprintf(char **result, const char *format, va_list args);
int asprintf(char **result, const char *format, ...);
#endif /* HAVE_ASPRINTF */

void run_script(Tcl_Interp *interp, char *fmt, ...);
void set_var(Tcl_Interp *interp, const char *var1, const char *var2, const char *fmt, ...);
void set_var2(Tcl_Interp *interp, const char *var1, const char *var2, const char *data, int len);

int cmd_rputs(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_rwrite(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_send_http_header(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_r(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_r_set(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_read_post(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_server_version(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_create_environment(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_abort(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_internal_redirect(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_random(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_srandom(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_base64_encode(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_base64_decode(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_allow_options(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_allow_overrides(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_default_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_document_root(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_remote_host(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_remote_logname(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_construct_url(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_server_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_server_port(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_limit_req_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_get_limit_xml_body(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_custom_response(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_exists_config_define(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_auth_type(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_auth_name(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_satisfies(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);
int cmd_ap_requires(ClientData cd, Tcl_Interp *ixx, int objc, Tcl_Obj *CONST objv[]);

#endif /* __MOD_TCL_H__ */
