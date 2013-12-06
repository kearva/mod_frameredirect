/*
   Copyright 2011-2013 Kent Are Varmedal, Jan Ingvoldstad

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   ******

   Project home page: https://github.com/kearva/mod_frameredirect
*/

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <string.h>

#define MOD_FRAMEREDIRECT_VERSION "20131206-02"

typedef struct {
	const char* url;
	const char* title;
	const char* description;
} frame_cfg;

module AP_MODULE_DECLARE_DATA frameredirect_module;

/*
 * is_alpha_char() checks whether a char is a part of the alphabet.
 */
int
is_alpha_char(char c)
{
  return ('A' <= c && 'Z' >= c || 'a' <= c && 'z' >= c);
}

/*
 * is_numberic_char() checks whether a char is a number
 */
int
is_numeric_char(char c)
{
  return ('0' <= c && '9' >= c);
}


/*
 * is_entity() checks whether a string is an HTML character entity
 */
int
is_entity(const char* str)
{
	int idx = 0, len = strlen(str);
	if (!len || str[0] != '&') return 0;
	if (len > 20) len = 20;

	while (++idx < len && is_alpha_char(str[idx]));
	if (str[idx] == ';') return (idx > 2); // End found, it's done.
	if (str[idx] == '#') { // It's a start of a numeric entity
		while(++idx < len && is_numeric_char(str[idx]));
		if(str[idx] == ';') return (idx > 2); 
	}
	return 0;
}

/*
 * escapestring() takes an input string, parses it and escapes/encodes
 * as HTML character entities any characters ('&','<','>','"') that
 * could cause problems in HTML or an HTML attribute, and which are not
 * already HTML character entities, even if they strictly speaking
 * should not appear in the server config.
 *
 * Examples:
 *   FrameRedirectTitle "<3 Sticks & Stones" => <TITLE>&lt;3 Sticks &amp; Stones</TITLE>
 *   FrameRedirectTitle Stones" => <TITLE>Stones&quot;</TITLE>
 *   FrameRedirectTitle "Sticks &amp; stones" => <TITLE>Sticks &amp; Stones</TITLE>
 *   FrameRedirectTitle "Sticks &#38; stones" => <TITLE>Sticks &#38; Stones</TITLE>
 */
char*
escapestring(apr_pool_t* pool,const char* str)
{
	int idx, cnt, len;

	/* Titles and descriptions may be NULL, don't attempt to parse */
	if (str == NULL) return NULL;

	len = strlen(str);

	/* Initial parsing to determine length of output string */
	for (idx = 0; str[idx] != '\0'; idx++) {
		switch(str[idx]) {
			case '&':
				if (!is_entity(&str[idx])) {
					len += 4;
				}
				break;
			case '<':
			case '>':
				len += 3;
				break;
			case '"':
				len += 5;
				break;
			default:
				break;
		}
	}

	// If we do not find any char to escape return str.
	if(len == strlen(str)) return (char*)str;

	char *out = apr_pcalloc(pool, len + 2);

	/* Encode the output string */
	for (idx = 0, cnt = 0; str[idx] != '\0'; idx++) {
		switch (str[idx]) {
			case '&':
				if (is_entity(&str[idx])) {
					out[cnt++] = '&';
				} else {
					out[cnt++] = '&';
					out[cnt++] = 'a';
					out[cnt++] = 'm';
					out[cnt++] = 'p';
					out[cnt++] = ';';
				}
				break;
			case '<':
				out[cnt++] = '&';
				out[cnt++] = 'l';
				out[cnt++] = 't';
				out[cnt++] = ';';
				break;

			case '>':
				out[cnt++] = '&';
				out[cnt++] = 'g';
				out[cnt++] = 't';
				out[cnt++] = ';';
				break;
			case '"':
				out[cnt++] = '&';
				out[cnt++] = 'q';
				out[cnt++] = 'u';
				out[cnt++] = 'o';
				out[cnt++] = 't';
				out[cnt++] = ';';
				break;
			default:
				out[cnt++] = str[idx];
		}
	}
	out[cnt++] = '\0';
	return out;
}

/*
 * frameredirect_handler() 
 */
static int
frameredirect_handler(request_rec* r)
{
	unsigned int alen, rlen, clen, urllen;
	char *args, *url, *uri, *description = NULL, *title;

	if (!r->handler || strncmp(r->handler, "frameredirect", 9))
		return DECLINED;

	/* Only permit GET requests */
	if (r->method_number != M_GET)
		return HTTP_METHOD_NOT_ALLOWED;

	frame_cfg* conf = ap_get_module_config(r->server->module_config, &frameredirect_module);

	if (!conf->url) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "mod_frameredirect: No url given for %s.", r->hostname); 
		return HTTP_FORBIDDEN;
	}

	alen = 0;
	rlen = strlen(r->uri);
	clen = strlen(conf->url);
	urllen = clen + rlen + 1;

	/* Handle arguments sanely, assumes the argument delimiter is a question mark */
	if (r->args) {
		alen = strlen(r->args);
		args = apr_pcalloc(r->pool, alen + 1);
		args[0] = '?';
		strncat(args, r->args, alen);
		args[alen + 1] = '\0';
		urllen += alen + 1;
	}

	if (clen == 0 || urllen < clen || urllen < rlen || urllen < alen) {
		/* Something is wrong with the string length, possible
		   buffer overflow */
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "mod_frameredirect: Possible buffer overflow on %s (a=%d, c=%d, r=%d, u=%d).", r->hostname, alen, clen, rlen, urllen); 
		return HTTP_FORBIDDEN;
	}

	url = apr_pcalloc(r->pool, urllen);

	strncpy(url, conf->url, clen);

	/*
	 * Avoid double slashes when merging URI with remote URL, and
	 * avoid extraneous slash at the end of a remote URL that
	 * itself doesn't end with a slash, while preserving any args
	 */
	if (rlen && r->uri[0] == '/' &&
	    (conf->url[clen - 1] == '/' ||
	     (alen && rlen == 1))) {
		strncat(url, ++r->uri, rlen - 1);
		url[clen + rlen - 1] = '\0';
	} else {
		if (rlen != 1 || r->uri[0] != '/') {
			strncat(url, r->uri, rlen);
			url[clen + rlen] = '\0';
		}
	}
	if (alen) {
		strncat(url, args, alen + 1);
	}

	ap_set_content_type(r, "text/html; charset=utf-8");

	// Escape the description and title if they are set.
	description = escapestring(r->pool,conf->description);
	if (! (title = escapestring(r->pool, conf->title))) {
		// The title is not set set the hostname insted.
		title = (char *)r->hostname;
	}

	ap_rputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\"\n", r);
	ap_rputs("                      \"http://www.w3.org/TR/html4/frameset.dtd\">\n", r);
	ap_rputs("<HTML>\n", r);
	ap_rputs("\t<HEAD>\n", r);
	ap_rprintf(r, "\t\t<!-- mod_frameredirect version %s -->\n", MOD_FRAMEREDIRECT_VERSION);
	ap_rprintf(r, "\t\t<TITLE>%s</TITLE>\n", title);
	ap_rputs("\t\t<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=utf-8\">\n", r);
	if (description) {
		ap_rprintf(r, "\t\t<META NAME=\"Description\" CONTENT=\"%s\">\n", description);
	}
	ap_rputs("\t</HEAD>\n", r);
	ap_rputs("\t<FRAMESET ROWS=\"100%,*\" STYLE=\"border: none 0px #ffffff; margin: 0; padding:0;\">\n", r);
	ap_rprintf(r, "\t\t<FRAME NAME=\"_main\" MARGINWIDTH=\"10\" MARGINHEIGHT=\"10\" SRC=\"%s\">\n" , url);
	ap_rputs("\t\t<NOFRAMES>\n", r);
	ap_rprintf(r, "\t\t\t<P>The document is located <A HREF=\"%s\">here</A>.</P>\n", url);
	ap_rputs("\t\t</NOFRAMES>\n", r);
	ap_rputs("\t</FRAMESET>\n", r);
	ap_rputs("</HTML>\n", r);

	return OK;
}

static void*
frameredirect_config(apr_pool_t* pool, server_rec* x)
{
	return apr_pcalloc(pool, sizeof(frame_cfg));
}

static void*
frameredirect_cfg_merge(apr_pool_t* pool, void* BASE, void* ADD)
{
	frame_cfg* base = (frame_cfg*) BASE;
	frame_cfg* add = (frame_cfg*) ADD;
	frame_cfg* conf = apr_pcalloc(pool, sizeof(frame_cfg));

	conf->url = add->url ? add->url : base->url;
	conf->title = add->title ? add->title : base->title;
	conf->description = add->description ? add->description : base->description;
	return conf;
}

static void
register_hooks(apr_pool_t* pool)
{
	ap_hook_handler(frameredirect_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char*
set_cfg_url(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->url = arg;
	return NULL;
}

static const char*
set_cfg_title(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->title = arg;
	return NULL;
}

static const char*
set_cfg_description(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->description = arg;
	return NULL;
}


static const char* 
set_cfg_all(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->url = arg1;
	s_cfg->title = arg2;
	s_cfg->description = arg3;
	return NULL;
}

static const command_rec frameredirect_cmds[] = {
   AP_INIT_TAKE1("FrameRedirectUrl", set_cfg_url,
 	NULL, RSRC_CONF, "Frame URL") ,
   AP_INIT_TAKE1("FrameRedirectTitle", set_cfg_title,
	NULL, RSRC_CONF, "Frame title") ,
   AP_INIT_TAKE1("FrameRedirectDescription", set_cfg_description,
	NULL, RSRC_CONF, "Frame description") ,
   AP_INIT_TAKE123("FrameRedirectConf", set_cfg_all, 
	NULL, RSRC_CONF, "Frame one line config") ,
   { NULL }
};

module AP_MODULE_DECLARE_DATA frameredirect_module = {
    STANDARD20_MODULE_STUFF,
    NULL, 			/* per-directory config creator */
    NULL, 			/* dir config merger */
    frameredirect_config, 	/* server config creator */
    frameredirect_cfg_merge, 	/* server config merger */
    frameredirect_cmds, 	/* command table */
    register_hooks 		/* set up other request processing hooks */
};
