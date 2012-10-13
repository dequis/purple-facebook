/**
 * @file http.c HTTP API
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301 USA
 */

#include "http.h"

#include "internal.h"
#include "debug.h"

typedef struct _PurpleHttpURL PurpleHttpURL;

typedef struct _PurpleHttpSocket PurpleHttpSocket;

typedef struct _PurpleHttpHeaders PurpleHttpHeaders;

struct _PurpleHttpSocket
{
	gboolean is_ssl;
	PurpleSslConnection *ssl_connection;
	PurpleProxyConnectData *raw_connection;
	int fd;
	guint inpa;
};

struct _PurpleHttpRequest
{
	int ref_count;

	gchar *url;
};

struct _PurpleHttpConnection
{
	PurpleConnection *gc;
	PurpleHttpCallback callback;
	gpointer user_data;

	PurpleHttpURL *url;
	PurpleHttpRequest *request;
	PurpleHttpResponse *response;

	PurpleHttpSocket socket;
	GString *request_header;
	int request_header_written;
	gboolean main_header_got, headers_got;
	GString *response_buffer;

	int length_expected, length_got;
};

struct _PurpleHttpResponse
{
	int code;
	gchar *error;

	GString *contents;
	PurpleHttpHeaders *headers;
};

struct _PurpleHttpURL
{
	gchar *protocol;
	gchar *host;
	int port;
	gchar *path;
	gchar *user;
	gchar *password;
};

struct _PurpleHttpHeaders
{
	GList *list;
	GHashTable *by_name;
};

static PurpleHttpConnection * purple_http_connection_new(
	PurpleHttpRequest *request);
static void purple_http_connection_terminate(PurpleHttpConnection *hc);

static PurpleHttpResponse * purple_http_response_new(void);
static void purple_http_response_free(PurpleHttpResponse *response);

static PurpleHttpURL * purple_http_url_parse(const char *url);
static void purple_http_url_free(PurpleHttpURL *parsed_url);

//static const gchar * purple_http_url_debug(PurpleHttpURL *parsed_url);

/*** Headers collection *******************************************************/

static PurpleHttpHeaders * purple_http_headers_new(void);
static void purple_http_headers_free(PurpleHttpHeaders *hdrs);
static void purple_http_headers_add(PurpleHttpHeaders *hdrs, const gchar *key,
	const gchar *value);
static const GList * purple_http_headers_get_all(PurpleHttpHeaders *hdrs);
static const gchar * purple_http_headers_get(PurpleHttpHeaders *hdrs,
	const gchar *key);
static gboolean purple_http_headers_get_int(PurpleHttpHeaders *hdrs,
	const gchar *key, int *dst);
static gchar * purple_http_headers_dump(PurpleHttpHeaders *hdrs);

static PurpleHttpHeaders * purple_http_headers_new(void)
{
	PurpleHttpHeaders *hdrs = g_new0(PurpleHttpHeaders, 1);

	hdrs->by_name = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
		(GDestroyNotify)g_list_free);

	return hdrs;
}

static void purple_http_headers_free_kvp(PurpleKeyValuePair *kvp)
{
	g_free(kvp->key);
	g_free(kvp->value);
	g_free(kvp);
}

static void purple_http_headers_free(PurpleHttpHeaders *hdrs)
{
	if (hdrs == NULL)
		return;

	g_hash_table_destroy(hdrs->by_name);
	g_list_free_full(hdrs->list,
		(GDestroyNotify)purple_http_headers_free_kvp);
	g_free(hdrs);
}

static void purple_http_headers_add(PurpleHttpHeaders *hdrs, const gchar *key,
	const gchar *value)
{
	PurpleKeyValuePair *kvp;
	GList *named_values;

	g_return_if_fail(hdrs != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(value != NULL);

	kvp = g_new0(PurpleKeyValuePair, 1);
	kvp->key = g_ascii_strdown(key, -1);
	key = kvp->key;
	kvp->value = g_strdup(value);
	hdrs->list = g_list_append(hdrs->list, kvp);

	named_values = g_hash_table_lookup(hdrs->by_name, key);
	named_values = g_list_append(named_values, kvp->value);
	g_hash_table_replace(hdrs->by_name, g_strdup(key), named_values);
}

static const GList * purple_http_headers_get_all(PurpleHttpHeaders *hdrs)
{
	return hdrs->list;
}

static const gchar * purple_http_headers_get(PurpleHttpHeaders *hdrs,
	const gchar *key)
{
	GList *values;

	g_return_val_if_fail(hdrs != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	values = g_hash_table_lookup(hdrs->by_name, key);
	if (!values)
		return NULL;

	return values->data;
}

static gboolean purple_http_headers_get_int(PurpleHttpHeaders *hdrs,
	const gchar *key, int *dst)
{
	int val;
	const gchar *str;

	str = purple_http_headers_get(hdrs, key);
	if (!str)
		return FALSE;

	if (1 != sscanf(str, "%d", &val))
		return FALSE;

	*dst = val;
	return TRUE;
}

static gchar * purple_http_headers_dump(PurpleHttpHeaders *hdrs)
{
	const GList *hdr;

	GString *s = g_string_new("");
	
	hdr = purple_http_headers_get_all(hdrs);
	while (hdr) {
		PurpleKeyValuePair *kvp = hdr->data;
		hdr = g_list_next(hdr);

		g_string_append_printf(s, "%s: %s%s", kvp->key,
			(gchar*)kvp->value, hdr ? "\n" : "");
	}
	
	return g_string_free(s, FALSE);
}

/*** HTTP protocol backend ****************************************************/

static void _purple_http_disconnect(PurpleHttpConnection *hc);

static void _purple_http_gen_headers(PurpleHttpConnection *hc);
static void _purple_http_recv(gpointer _hc, gint fd, PurpleInputCondition cond);
static void _purple_http_recv_ssl(gpointer _hc,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond);
static void _purple_http_send(gpointer _hc, gint fd, PurpleInputCondition cond);

static void _purple_http_connected_raw(gpointer _hc, gint source,
	const gchar *error_message);
static void _purple_http_connected_ssl(gpointer _hc,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond);
static void _purple_http_connected_ssl_error(
	PurpleSslConnection *ssl_connection, PurpleSslErrorType error,
	gpointer _hc);

/* closes current connection (if exists), estabilishes one and proceeds with
 * request */
static gboolean _purple_http_reconnect(PurpleHttpConnection *hc);

static void _purple_http_error(PurpleHttpConnection *hc, const char *format,
	...) G_GNUC_PRINTF(2, 3);

static void _purple_http_error(PurpleHttpConnection *hc, const char *format,
	...)
{
	va_list args;

	va_start(args, format);
	hc->response->error = g_strdup_vprintf(format, args);
	va_end(args);

	purple_http_conn_cancel(hc);
}

static void _purple_http_gen_headers(PurpleHttpConnection *hc)
{
	GString *h;
	PurpleHttpURL *url;
	PurpleProxyInfo *proxy;

	g_return_if_fail(hc != NULL);

	if (hc->request_header != NULL)
		return;

	url = hc->url;
	proxy = purple_proxy_get_setup(hc->gc ?
		purple_connection_get_account(hc->gc) : NULL);

	hc->request_header = h = g_string_new("");
	hc->request_header_written = 0;

	g_string_append_printf(h, "GET %s HTTP/%s\r\n", url->path, "1.1");
	g_string_append_printf(h, "Host: %s\r\n", url->host);
	g_string_append_printf(h, "Connection: close\r\n");

	/* TODO: don't put here, if exists */
	g_string_append_printf(h, "Accept: */*\r\n");


	if (purple_proxy_info_get_username(proxy) != NULL &&
		(purple_proxy_info_get_type(proxy) == PURPLE_PROXY_USE_ENVVAR ||
		purple_proxy_info_get_type(proxy) == PURPLE_PROXY_HTTP)) {
		purple_debug_error("http",
			"Proxy authorization is not yet supported\n");
	}

	g_string_append_printf(h, "\r\n");

	if (purple_debug_is_unsafe() && purple_debug_is_verbose()) {
		purple_debug_misc("http", "Generated request headers:\n%s",
			h->str);
	}
}

static gboolean _purple_http_recv_headers(PurpleHttpConnection *hc,
	const gchar *buf, int len)
{
	gchar *eol, *delim;

	g_string_append_len(hc->response_buffer, buf, len); //TODO: check max buffer length, not to raise to infinity
	while ((eol = strstr(hc->response_buffer->str, "\r\n"))
		!= NULL) {
		gchar *hdrline = hc->response_buffer->str;
		int hdrline_len = eol - hdrline;

		hdrline[hdrline_len] = '\0';

		if (hdrline[0] == '\0') {
			if (!hc->main_header_got) {
				hc->response->code = 0;
				purple_debug_warning("http",
					"Main header not present\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
				return FALSE;
			}
			hc->headers_got = TRUE;
			if (purple_debug_is_verbose())
				purple_debug_misc("http", "Got headers end\n");
		} else if (!hc->main_header_got) {
			hc->main_header_got = TRUE;
			delim = strchr(hdrline, ' ');
			if (delim == NULL || 1 != sscanf(delim + 1, "%d",
				&hc->response->code)) {
				purple_debug_warning("http",
					"Invalid response code\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
				return FALSE;
			}
			if (purple_debug_is_verbose())
				purple_debug_misc("http", "Got main header\n");
		} else {
			if (purple_debug_is_verbose() &&
				purple_debug_is_unsafe())
				purple_debug_misc("http", "Got header: %s\n",
					hdrline);
			delim = strchr(hdrline, ':');
			if (delim == NULL || delim == hdrline) {
				purple_debug_warning("http",
					"Bad header delimiter\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
				return FALSE;
			}
			*delim++ = '\0';
			while (*delim == ' ')
				delim++;
			
			purple_http_headers_add(hc->response->headers, hdrline, delim);
		}

		g_string_erase(hc->response_buffer, 0, hdrline_len + 2);
		if (hc->headers_got)
			break;
	}
	return TRUE;
}

static void _purple_http_recv_body(PurpleHttpConnection *hc,
	const gchar *buf, int len)
{
	if (hc->response->contents == NULL)
		hc->response->contents = g_string_new("");

	/* TODO: chunked data, body length etc */

	if (len + hc->length_got > hc->length_expected)
		len = hc->length_expected - hc->length_got;
	hc->length_got += len;

	g_string_append_len(hc->response->contents, buf, len);
}

static void _purple_http_recv(gpointer _hc, gint fd, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;
	int len;
	gchar buf[4096];

	purple_debug_misc("http", "[tmp] reading...\n");

	if (hs->is_ssl)
		len = purple_ssl_read(hs->ssl_connection, buf, sizeof(buf));
	else
		len = read(fd, buf, sizeof(buf));

	if (len < 0 && errno == EAGAIN)
		return;

	if (len < 0) {
		_purple_http_error(hc, _("Error reading from %s: %s"),
			hc->url->host, g_strerror(errno));
		return;
	}

	if (len == 0 && hc->length_expected < 0 && hc->headers_got)
		hc->length_expected = hc->length_got;

	if (!hc->headers_got && len > 0) {
		if (!_purple_http_recv_headers(hc, buf, len))
			return;
		if (hc->headers_got && hc->response_buffer &&
			hc->response_buffer->len > 0) {
			_purple_http_recv_body(hc, hc->response_buffer->str,
				hc->response_buffer->len);
			g_string_truncate(hc->response_buffer, 0);
		}
		if (hc->headers_got) {
			if (!purple_http_headers_get_int(hc->response->headers,
				"Content-Length", &hc->length_expected))
				hc->length_expected = -1;
		}
		return;
	}

	if (len > 0)
		_purple_http_recv_body(hc, buf, len);

	if (hc->length_got >= hc->length_expected) {
		if (!hc->headers_got) {
			hc->response->code = 0;
			purple_debug_warning("http", "No headers got\n");
			_purple_http_error(hc, _("Error parsing HTTP"));
			return;
		}

		if (purple_debug_is_unsafe() && purple_debug_is_verbose()) {
			gchar *hdrs = purple_http_headers_dump(
				hc->response->headers);
			purple_debug_misc("http", "Got response headers: %s\n",
				hdrs);
			g_free(hdrs);
		}

		_purple_http_disconnect(hc);
		purple_http_connection_terminate(hc);
		return;
	}
}

static void _purple_http_recv_ssl(gpointer _hc,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	_purple_http_recv(_hc, -1, cond);
}

static void _purple_http_send(gpointer _hc, gint fd, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;
	int written, write_len;
	const gchar *write_from;

	_purple_http_gen_headers(hc);

	purple_debug_misc("http", "[tmp] sending...\n");

	write_from = hc->request_header->str + hc->request_header_written;
	write_len = hc->request_header->len - hc->request_header_written;

	if (hs->is_ssl)
		written = purple_ssl_write(hs->ssl_connection,
			write_from, write_len);
	else
		written = write(hs->fd, write_from, write_len);

	if (written < 0 && errno == EAGAIN)
		return;

	if (written < 0) {
		_purple_http_error(hc, _("Error writing to %s: %s"),
			hc->url->host, g_strerror(errno));
		return;
	}

	hc->request_header_written += written;
	if (hc->request_header_written < hc->request_header->len)
		return;

	/* TODO: write contents */

	/* request is completely written, let's read the response */
	purple_input_remove(hs->inpa);
	hs->inpa = 0;
	if (hs->is_ssl)
		purple_ssl_input_add(hs->ssl_connection,
			_purple_http_recv_ssl, hc);
	else
		hs->inpa = purple_input_add(hs->fd, PURPLE_INPUT_READ,
			_purple_http_recv, hc);
}

static void _purple_http_connected_raw(gpointer _hc, gint fd,
	const gchar *error_message)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;

	hs->raw_connection = NULL;

	if (fd == -1) {
		_purple_http_error(hc, _("Unable to connect to %s: %s"),
			hc->url->host, error_message);
		return;
	}

	hs->fd = fd;
	hs->inpa = purple_input_add(fd, PURPLE_INPUT_WRITE,
		_purple_http_send, hc);
}

static void _purple_http_connected_ssl(gpointer _hc,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;

	hs->fd = hs->ssl_connection->fd;
	hs->inpa = purple_input_add(hs->fd, PURPLE_INPUT_WRITE,
		_purple_http_send, hc);
}

static void _purple_http_connected_ssl_error(
	PurpleSslConnection *ssl_connection, PurpleSslErrorType error,
	gpointer _hc)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;

	hs->ssl_connection = NULL;
	_purple_http_error(hc, _("Unable to connect to %s: %s"),
		hc->url->host, purple_ssl_strerror(error));
}

static void _purple_http_disconnect(PurpleHttpConnection *hc)
{
	PurpleHttpSocket *hs;

	g_return_if_fail(hc != NULL);

	hs = &hc->socket;

	if (hc->request_header)
		g_string_free(hc->request_header, TRUE);
	hc->request_header = NULL;
	if (hc->response_buffer)
		g_string_free(hc->response_buffer, TRUE);
	hc->response_buffer = NULL;

	if (hs->inpa != 0)
		purple_input_remove(hs->inpa);

	if (hs->is_ssl) {
		if (hs->ssl_connection != NULL)
			purple_ssl_close(hs->ssl_connection);
	} else {
		if (hs->raw_connection != NULL)
			purple_proxy_connect_cancel(hs->raw_connection);
		if (hs->fd > 0)
			close(hs->fd);
	}

	memset(hs, 0, sizeof(PurpleHttpSocket));
}

static gboolean _purple_http_reconnect(PurpleHttpConnection *hc)
{
	PurpleHttpURL *url;
	gboolean is_ssl = FALSE;
	PurpleAccount *account = NULL;

	g_return_val_if_fail(hc != NULL, FALSE);
	g_return_val_if_fail(hc->url != NULL, FALSE);

	_purple_http_disconnect(hc);

	if (hc->gc)
		account = purple_connection_get_account(hc->gc);

	url = hc->url;
	if (url->protocol[0] == '\0' ||
		g_ascii_strcasecmp(url->protocol, "http") == 0) {
		/* do nothing */
	} else if (g_ascii_strcasecmp(url->protocol, "https") == 0) {
		is_ssl = TRUE;
	} else {
		_purple_http_error(hc, _("Unsupported protocol: %s"),
			url->protocol);
		return FALSE;
	}

	hc->socket.is_ssl = is_ssl;
	if (is_ssl) {
		if (!purple_ssl_is_supported()) {
			_purple_http_error(hc, _("Unable to connect to %s: %s"),
				url->host, _("Server requires TLS/SSL, "
				"but no TLS/SSL support was found."));
			return FALSE;
		}
		hc->socket.ssl_connection = purple_ssl_connect(account,
			url->host, url->port,
			_purple_http_connected_ssl,
			_purple_http_connected_ssl_error, hc);
	} else {
		hc->socket.raw_connection = purple_proxy_connect(hc->gc, account,
			url->host, url->port,
			_purple_http_connected_raw, hc);
	}

	if (hc->socket.ssl_connection == NULL &&
		hc->socket.raw_connection == NULL) {
		_purple_http_error(hc, _("Unable to connect to %s"), url->host);
		return FALSE;
	}

	purple_http_headers_free(hc->response->headers);
	hc->response->headers = purple_http_headers_new();
	hc->response_buffer = g_string_new("");
	hc->main_header_got = FALSE;
	hc->headers_got = FALSE;
	if (hc->response->contents != NULL)
		g_string_free(hc->response->contents, TRUE);
	hc->response->contents = NULL;
	hc->length_got = 0;
	hc->length_expected = -1;

	return TRUE;
}

/*** Performing HTTP requests *************************************************/

PurpleHttpConnection * purple_http_get(PurpleConnection *gc, const gchar *url,
	PurpleHttpCallback callback, gpointer user_data)
{
	PurpleHttpRequest *request;
	PurpleHttpConnection *hc;

	g_return_val_if_fail(url != NULL, NULL);

	request = purple_http_request_new(url);
	hc = purple_http_request(gc, request, callback, user_data);
	purple_http_request_unref(request);

	return hc;
}

PurpleHttpConnection * purple_http_request(PurpleConnection *gc,
	PurpleHttpRequest *request, PurpleHttpCallback callback,
	gpointer user_data)
{
	PurpleHttpConnection *hc;

	g_return_val_if_fail(request != NULL, NULL);

	hc = purple_http_connection_new(request);
	hc->gc = gc;
	hc->callback = callback;
	hc->user_data = user_data;

	if (purple_debug_is_unsafe())
		purple_debug_misc("http", "Performing new request %p for %s.\n",
			hc, request->url);
	else
		purple_debug_misc("http", "Performing new request %p.\n", hc);

	hc->url = purple_http_url_parse(request->url);
	if (!hc->url || hc->url->host[0] == '\0') {
		purple_debug_error("http", "Invalid URL requested.\n");
		purple_http_connection_terminate(hc);
		return NULL;
	}

	_purple_http_reconnect(hc);

	/* TODO: timeout */

	return hc;
}

/*** HTTP connection API ******************************************************/

static void purple_http_connection_free(PurpleHttpConnection *hc);

static PurpleHttpConnection * purple_http_connection_new(PurpleHttpRequest *request)
{
	PurpleHttpConnection *hc = g_new0(PurpleHttpConnection, 1);

	hc->request = request;
	purple_http_request_ref(request);
	hc->response = purple_http_response_new();

	return hc;
}

static void purple_http_connection_free(PurpleHttpConnection *hc)
{
	purple_http_url_free(hc->url);
	purple_http_request_unref(hc->request);
	purple_http_response_free(hc->response);

	if (hc->request_header)
		g_string_free(hc->request_header, TRUE);

	g_free(hc);
}

/* call callback and do the cleanup */
static void purple_http_connection_terminate(PurpleHttpConnection *hc)
{
	g_return_if_fail(hc != NULL);

	purple_debug_misc("http", "Request %p performed %s.\n", hc,
		purple_http_response_is_successfull(hc->response) ?
		"successfully" : "without success");

	if (hc->callback)
		hc->callback(hc, hc->response, hc->user_data);

	purple_http_connection_free(hc);
}

void purple_http_conn_cancel(PurpleHttpConnection *http_conn)
{
	http_conn->response->code = 0;
	_purple_http_disconnect(http_conn);
	purple_http_connection_terminate(http_conn);
}

void purple_http_conn_cancel_all(PurpleConnection *gc)
{
	purple_debug_warning("http", "purple_http_conn_cancel_all: To be implemented\n");
}

/*** Request API **************************************************************/

static void purple_http_request_free(PurpleHttpRequest *request);

PurpleHttpRequest * purple_http_request_new(const gchar *url)
{
	PurpleHttpRequest *request;

	g_return_val_if_fail(url != NULL, NULL);

	request = g_new0(PurpleHttpRequest, 1);

	request->ref_count = 1;
	request->url = g_strdup(url);

	return request;
}

static void purple_http_request_free(PurpleHttpRequest *request)
{
	g_free(request->url);
	g_free(request);
}

void purple_http_request_ref(PurpleHttpRequest *request)
{
	g_return_if_fail(request != NULL);

	request->ref_count++;
}

PurpleHttpRequest * purple_http_request_unref(PurpleHttpRequest *request)
{
	if (request == NULL)
		return NULL;

	g_return_val_if_fail(request->ref_count > 0, NULL);

	request->ref_count--;
	if (request->ref_count > 0)
		return request;

	purple_http_request_free(request);
	return NULL;
}

/*** HTTP response API ********************************************************/

static PurpleHttpResponse * purple_http_response_new(void)
{
	PurpleHttpResponse *response = g_new0(PurpleHttpResponse, 1);

	return response;
}

static void purple_http_response_free(PurpleHttpResponse *response)
{
	if (response->contents != NULL)
		g_string_free(response->contents, TRUE);
	g_free(response->error);
	purple_http_headers_free(response->headers);
	g_free(response);
}

gboolean purple_http_response_is_successfull(PurpleHttpResponse *response)
{
	int code;

	g_return_val_if_fail(response != NULL, FALSE);

	code = response->code;

	if (code <= 0)
		return FALSE;

	if (code == 200)
		return TRUE;

	if (code / 100 == 3) /* 3xx */
		return TRUE;

	return FALSE;
}

int purple_http_response_get_code(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, 0);

	return response->code;
}

const gchar * purple_http_response_get_error(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, NULL);

	return response->error;
}

gsize purple_http_response_get_data_len(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, 0);

	if (response->contents == NULL)
		return 0;

	return response->contents->len;
}

const gchar * purple_http_response_get_data(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, NULL);

	if (response->contents == NULL)
		return "";

	return response->contents->str;
}

/*** URL functions ************************************************************/

static PurpleHttpURL * purple_http_url_parse(const char *url)
{
	PurpleHttpURL *parsed_url;

	g_return_val_if_fail(url != NULL, NULL);

	parsed_url = g_new0(PurpleHttpURL, 1);

	if (!purple_url_parse(url,
		&parsed_url->protocol,
		&parsed_url->host,
		&parsed_url->port,
		&parsed_url->path,
		&parsed_url->user,
		&parsed_url->password)) {
		g_free(parsed_url);
		return NULL;
	}

	if (parsed_url->host[0] != '\0' &&
		parsed_url->path[0] != '\0') {
		gchar *tmp = parsed_url->path;
		parsed_url->path = g_strdup_printf("/%s", parsed_url->path);
		g_free(tmp);
	}

	if (parsed_url->path[0] == '\0') {
		g_free(parsed_url->path);
		parsed_url->path = g_strdup("/");
	}

	return parsed_url;
}

static void purple_http_url_free(PurpleHttpURL *parsed_url)
{
	if (parsed_url == NULL)
		return;

	g_free(parsed_url->protocol);
	g_free(parsed_url->host);
	g_free(parsed_url->path);
	g_free(parsed_url->user);
	g_free(parsed_url->password);
	g_free(parsed_url);
}

/*
static const gchar * purple_http_url_debug(PurpleHttpURL *parsed_url)
{
	static gchar buff[512];

	g_return_val_if_fail(parsed_url != NULL, "(null)");

	g_snprintf(buff, sizeof(buff), "%s://%s:%d [%s] [%s / %s]",
		parsed_url->protocol,
		parsed_url->host,
		parsed_url->port,
		parsed_url->path,
		parsed_url->user,
		parsed_url->password);

	buff[sizeof(buff) - 1] = '\0';

	return buff;
}
*/

