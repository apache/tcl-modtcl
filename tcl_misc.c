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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef HAVE_ASPRINTF
// ripped from gcc
int int_vasprintf(char **result, const char *format, va_list *args)
{
	const char *p = format;
  /* Add one to make sure that it is never zero, which might cause malloc
     to return NULL.  */
	int total_width = strlen(format) + 1;
	va_list ap;

	memcpy((char*) &ap, (char*) args, sizeof(va_list));

	while (*p != '\0') {
		if (*p++ == '%') {
			while (strchr ("-+ #0", *p)) {
            	++p;
            }

			if (*p == '*') {
				++p;
				total_width += abs(va_arg(ap, int));
			}
			else {
				total_width += (unsigned long) strtol(p, (char**) &p, 10);
			}
			
			if (*p == '.') {
				++p;

				if (*p == '*') {
					++p;
					total_width += abs(va_arg(ap, int));
				}
				else {
              		total_width += (unsigned long) strtol(p, (char**) &p, 10);
              	}
			}
         
			while (strchr ("hlL", *p)) {
				++p;
			}
			
			/* Should be big enough for any format specifier except %s and floats.  */
			total_width += 30;

			switch (*p) {
			  case 'd':
			  case 'i':
			  case 'o':
			  case 'u':
			  case 'x':
			  case 'X':
			  case 'c':
				(void) va_arg(ap, int);
				break;
			  case 'f':
			  case 'e':
			  case 'E':
			  case 'g':
			  case 'G':
				(void) va_arg(ap, double);
              /* Since an ieee double can have an exponent of 307, we'll
                 make the buffer wide enough to cover the gross case. */
				total_width += 307;
				break;
			  case 's':
				total_width += strlen(va_arg(ap, char*));
				break;
			  case 'p':
			  case 'n':
				(void) va_arg(ap, char*);
				break;
			}
		}
	}

	*result = (char*) malloc(total_width);

	if (*result != NULL) {
		return vsprintf(*result, format, *args);
	}
	else {
		return 0;
	}
}

int vasprintf(char **result, const char *format, va_list args)
{
	return int_vasprintf(result, format, &args);
}

int asprintf(char **result, const char *format, ...)
{
	va_list va;
	int ret;
	
	va_start(va, format);
	ret = vasprintf(result, format, va);
	va_end(va);
	
	return ret;
}
#endif /* HAVE_ASPRINTF */
