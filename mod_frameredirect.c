#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <string.h>

typedef struct {
	const char* url ;
	const char* title ;
	const char* description ;
} frame_cfg ;

module AP_MODULE_DECLARE_DATA frameredirect_module ;

int isAlpa(char c)
{
  return ('A' <= c && 'Z' >= c || 'a' <= c && 'z' >= c);
}

int isEscaped(const char* str)
{
	int idx, len = strlen(str);
	if (!len || str[0] != '&') return 0;
	if (len > 10) len = 10;

	while(++idx < len && isAlpha(str[idx])) {
		if(str[idx] == ';') return (idx > 2);
	}
	return 0;
}

char* escapestring(apr_pool_t* pool,const char* str)
{
	int idx, cnt, len;

	if (str == NULL) return NULL;

	len = strlen(str);

	for(idx = 0; str[idx] != '\0'; idx++) {
		switch(str[idx]) {
			case '&':
				if(!isEscaped(&str[idx])) {
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

	char *out = apr_palloc(pool, len + 2);

	cnt = 0;
	for(idx = 0; str[idx] != '\0'; idx++) {
		switch (str[idx]) {
			case '&':
				if(isEscaped(&str[idx])) {
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

static int frameredirect_handler(request_rec* r)
{
	unsigned int rlen, clen, urllen ;
	char *url, *description = NULL, *title ;

	if (!r->handler || strncmp(r->handler, "frameredirect", 9))
		return DECLINED;

	if (r->method_number != M_GET)
		return HTTP_METHOD_NOT_ALLOWED;

	frame_cfg* conf = ap_get_module_config(r->server->module_config, &frameredirect_module) ;

	if(!conf->url) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "mod_frameredirect: No url given for %s", r->hostname); 
		return HTTP_FORBIDDEN;
	}

	rlen = strlen(r->uri);
	clen = strlen(conf->url);
	urllen = clen + rlen + 10;

	if(urllen < clen || urllen < rlen) {
		// Something is wrong with the string lengh, possible bufferoverflow
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "mod_frameredirect: Possible buffer overflow"); 
		return HTTP_FORBIDDEN;
	}

	url = apr_palloc(r->pool, urllen);

	if(r->uri[0] == '/' && conf->url[clen-1] == '/') {
		strncpy(url, conf->url, clen - 1);
		url[clen-1] = '\0';
		strncat(url, r->uri, rlen);
	} else {
		strncpy(url, conf->url, clen);
		strncat(url, r->uri, rlen);
	}

	ap_set_content_type(r, "text/html; charset=utf-8");

	// Escape the description and title if they are set.
	description = escapestring(r->pool,conf->description);
	if (! title = escapestring(r->pool, conf->title)) {
		// The title is not set set the hostname insted.
		title = (char *)r->hostname;
	}

	ap_rputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\"\n", r);
	ap_rputs("                      \"http://www.w3.org/TR/html4/frameset.dtd\">\n", r);
	ap_rputs("<HTML>\n", r);
	ap_rputs("  <HEAD>\n", r);
	ap_rprintf(r, "    <TITLE>%s</TITLE>", title);
	if(description) {
		ap_rprintf(r, "    <META NAME=\"Description\" CONTENT=\"%s\">\n", description);
	}
	ap_rputs("  </HEAD>\n", r);
	ap_rputs("  <FRAMESET ROWS=\"100%,*\" STYLE=\"border: none 0px #ffffff; margin: 0; padding:0;\">\n", r);
	ap_rprintf(r, "    <FRAME NAME=\"_main\" MARGINWIDTH=\"10\" MARGINHEIGHT=\"10\" SRC=\"%s\">\n" , url);
	ap_rputs("    <NOFRAMES>\n", r);
	ap_rprintf(r, "    <P>The document is located <A HREF=\"%s\">here</A>.</P>\n", url);
	ap_rputs("    </NOFRAMES>\n", r);
	ap_rputs("  </FRAMESET>\n", r);
	ap_rputs("</HTML>\n", r);

	return OK;
}

static void* frameredirect_config(apr_pool_t* pool, char* x)
{
	return apr_pcalloc(pool, sizeof(frame_cfg)) ;
}

static void* frameredirect_cfg_merge(apr_pool_t* pool, void* BASE, void* ADD)
{
	frame_cfg* base = (frame_cfg*) BASE ;
	frame_cfg* add = (frame_cfg*) ADD ;
	frame_cfg* conf = apr_palloc(pool, sizeof(frame_cfg)) ;

	conf->url = add->url ? add->url : base->url ;
	conf->title = add->title ? add->title : base->title ;
	conf->description = add->description ? add->description : base->description ;
	return conf ;
}

static void register_hooks(apr_pool_t* pool)
{
	ap_hook_handler(frameredirect_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_cfg_url(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->url = arg;
	return NULL;
}

static const char *set_cfg_title(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->title = arg;
	return NULL;
}

static const char *set_cfg_description(cmd_parms *parms, void *mconfig, const char *arg)
{
	frame_cfg *s_cfg = ap_get_module_config(parms->server->module_config, &frameredirect_module);
	s_cfg->description = arg;
	return NULL;
}

static const command_rec frameredirect_cmds[] = {
   AP_INIT_TAKE1("FrameRedirectUrl", set_cfg_url,
 	NULL, RSRC_CONF, "Frame url") ,
   AP_INIT_TAKE1("FrameRedirectTitle", set_cfg_title,
	NULL, RSRC_CONF, "Frame title") ,
   AP_INIT_TAKE1("FrameRedirectDescription", set_cfg_description,
	NULL, RSRC_CONF, "Frame description") ,
   { NULL }
} ;

module AP_MODULE_DECLARE_DATA frameredirect_module = {
    STANDARD20_MODULE_STUFF,
    NULL, 			/* per-directory config creator */
    NULL, 			/* dir config merger */
    frameredirect_config, 	/* server config creator */
    frameredirect_cfg_merge, 	/* server config merger */
    frameredirect_cmds, 	/* command table */
    register_hooks 		/* set up other request processing hooks */
};
