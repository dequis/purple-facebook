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
#include "glibcompat.h"

#include "debug.h"
#include "ntlm.h"

#define PURPLE_HTTP_URL_CREDENTIALS_CHARS "a-z0-9.,~_/*!&%?=+\\^-"
#define PURPLE_HTTP_MAX_RECV_BUFFER_LEN 10240
#define PURPLE_HTTP_MAX_READ_BUFFER_LEN 10240

#define PURPLE_HTTP_REQUEST_DEFAULT_MAX_REDIRECTS 20
#define PURPLE_HTTP_REQUEST_DEFAULT_TIMEOUT 30
#define PURPLE_HTTP_REQUEST_DEFAULT_MAX_LENGTH 1048576

#define PURPLE_HTTP_PROGRESS_WATCHER_DEFAULT_INTERVAL 250000

typedef struct _PurpleHttpSocket PurpleHttpSocket;

typedef struct _PurpleHttpHeaders PurpleHttpHeaders;

typedef struct _PurpleHttpKeepaliveHost PurpleHttpKeepaliveHost;

typedef struct _PurpleHttpKeepaliveRequest PurpleHttpKeepaliveRequest;

typedef void (*PurpleHttpSocketConnectCb)(PurpleHttpSocket *hs,
	const gchar *error, gpointer user_data);

struct _PurpleHttpSocket
{
	gboolean is_ssl;
	gboolean is_busy;
	guint use_count;
	PurpleHttpKeepaliveHost *host;

	PurpleSslConnection *ssl_connection;
	PurpleProxyConnectData *raw_connection;
	int fd;
	guint inpa;
	PurpleInputFunction watch_cb;
	PurpleHttpSocketConnectCb connect_cb;
	gpointer cb_data;
};

struct _PurpleHttpRequest
{
	int ref_count;

	gchar *url;
	gchar *method;
	PurpleHttpHeaders *headers;
	PurpleHttpCookieJar *cookie_jar;
	PurpleHttpKeepalivePool *keepalive_pool;

	gchar *contents;
	int contents_length;
	PurpleHttpContentReader contents_reader;
	gpointer contents_reader_data;
	PurpleHttpContentWriter response_writer;
	gpointer response_writer_data;

	int timeout;
	int max_redirects;
	gboolean http11;
	int max_length;
};

struct _PurpleHttpConnection
{
	PurpleConnection *gc;
	PurpleHttpCallback callback;
	gpointer user_data;
	gboolean is_reading;
	gboolean is_keepalive;
	gboolean is_cancelling;

	PurpleHttpURL *url;
	PurpleHttpRequest *request;
	PurpleHttpResponse *response;

	PurpleHttpKeepaliveRequest *socket_request;
	PurpleHttpConnectionSet *connection_set;
	PurpleHttpSocket *socket;
	GString *request_header;
	int request_header_written, request_contents_written;
	gboolean main_header_got, headers_got;
	GString *response_buffer;

	GString *contents_reader_buffer;
	gboolean contents_reader_requested;

	int redirects_count;

	int length_expected, length_got;

	gboolean is_chunked, in_chunk, chunks_done;
	int chunk_length, chunk_got;

	GList *link_global, *link_gc;

	guint timeout_handle;

	PurpleHttpProgressWatcher watcher;
	gpointer watcher_user_data;
	guint watcher_interval_threshold;
	gint64 watcher_last_call;
	guint watcher_delayed_handle;
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
	gchar *username;
	gchar *password;
	gchar *host;
	int port;
	gchar *path;
	gchar *fragment;
};

struct _PurpleHttpHeaders
{
	GList *list;
	GHashTable *by_name;
};

typedef struct
{
	time_t expires;
	gchar *value;
} PurpleHttpCookie;

struct _PurpleHttpCookieJar
{
	int ref_count;

	GHashTable *tab;
};

struct _PurpleHttpKeepaliveRequest
{
	PurpleConnection *gc;
	PurpleHttpSocketConnectCb cb;
	gpointer user_data;

	PurpleHttpKeepaliveHost *host;
	PurpleHttpSocket *hs;
};

struct _PurpleHttpKeepaliveHost
{
	PurpleHttpKeepalivePool *pool;

	gchar *host;
	int port;
	gboolean is_ssl;

	GSList *sockets; /* list of PurpleHttpSocket */

	GSList *queue; /* list of PurpleHttpKeepaliveRequest */
	guint process_queue_timeout;
};

struct _PurpleHttpKeepalivePool
{
	gboolean is_destroying;

	int ref_count;

	guint limit_per_host;

	/* key: purple_http_socket_hash, value: PurpleHttpKeepaliveHost */
	GHashTable *by_hash;
};

struct _PurpleHttpConnectionSet
{
	gboolean is_destroying;

	GHashTable *connections;
};

static time_t purple_http_rfc1123_to_time(const gchar *str);

static gboolean purple_http_request_is_method(PurpleHttpRequest *request,
	const gchar *method);

static PurpleHttpConnection * purple_http_connection_new(
	PurpleHttpRequest *request, PurpleConnection *gc);
static void purple_http_connection_terminate(PurpleHttpConnection *hc);
static void purple_http_conn_notify_progress_watcher(PurpleHttpConnection *hc);
static void
purple_http_conn_retry(PurpleHttpConnection *http_conn);

static PurpleHttpResponse * purple_http_response_new(void);
static void purple_http_response_free(PurpleHttpResponse *response);

static void purple_http_cookie_jar_parse(PurpleHttpCookieJar *cookie_jar,
	GList *values);
static gchar * purple_http_cookie_jar_gen(PurpleHttpCookieJar *cookie_jar);
gchar * purple_http_cookie_jar_dump(PurpleHttpCookieJar *cjar);

static PurpleHttpKeepaliveRequest *
purple_http_keepalive_pool_request(PurpleHttpKeepalivePool *pool,
	PurpleConnection *gc, const gchar *host, int port, gboolean is_ssl,
	PurpleHttpSocketConnectCb cb, gpointer user_data);
static void
purple_http_keepalive_pool_request_cancel(PurpleHttpKeepaliveRequest *req);
static void
purple_http_keepalive_pool_release(PurpleHttpSocket *hs, gboolean invalidate);

static void
purple_http_connection_set_remove(PurpleHttpConnectionSet *set,
	PurpleHttpConnection *http_conn);

static GRegex *purple_http_re_url, *purple_http_re_url_host,
	*purple_http_re_rfc1123;

/**
 * Values: pointers to running PurpleHttpConnection.
 */
static GList *purple_http_hc_list;

/**
 * Keys: pointers to PurpleConnection.
 * Values: GList of pointers to running PurpleHttpConnection.
 */
static GHashTable *purple_http_hc_by_gc;

/**
 * Keys: pointers to PurpleConnection.
 * Values: gboolean TRUE.
 */
static GHashTable *purple_http_cancelling_gc;

/**
 * Keys: pointers to PurpleHttpConnection.
 * Values: pointers to links in purple_http_hc_list.
 */
static GHashTable *purple_http_hc_by_ptr;

/*** Helper functions *********************************************************/

static time_t purple_http_rfc1123_to_time(const gchar *str)
{
	static const gchar *months[13] = {"jan", "feb", "mar", "apr", "may", "jun",
		"jul", "aug", "sep", "oct", "nov", "dec", NULL};
	GMatchInfo *match_info;
	gchar *d_date, *d_month, *d_year, *d_time;
	int month;
	gchar *iso_date;
	time_t t;

	g_return_val_if_fail(str != NULL, 0);

	g_regex_match(purple_http_re_rfc1123, str, 0, &match_info);
	if (!g_match_info_matches(match_info)) {
		g_match_info_free(match_info);
		return 0;
	}
	g_match_info_free(match_info);

	d_date = g_match_info_fetch(match_info, 1);
	d_month = g_match_info_fetch(match_info, 2);
	d_year = g_match_info_fetch(match_info, 3);
	d_time = g_match_info_fetch(match_info, 4);

	month = 0;
	while (months[month] != NULL)
	{
		if (0 == g_ascii_strcasecmp(d_month, months[month]))
			break;
		month++;
	}
	month++;

	iso_date = g_strdup_printf("%s-%02d-%sT%s+00:00", 
		d_year, month, d_date, d_time);

	g_free(d_date);
	g_free(d_month);
	g_free(d_year);
	g_free(d_time);

	if (month > 12) {
		purple_debug_warning("http", "Invalid month: %s\n", d_month);
		g_free(iso_date);
		return 0;
	}

	t = purple_str_to_time(iso_date, TRUE, NULL, NULL, NULL);

	g_free(iso_date);

	return t;
}

/*** HTTP Sockets *************************************************************/

static void _purple_http_socket_connected_raw(gpointer _hs, gint fd,
	const gchar *error_message)
{
	PurpleHttpSocket *hs = _hs;

	hs->raw_connection = NULL;

	if (fd == -1 || error_message != NULL) {
		if (error_message == NULL)
			error_message = _("Unknown error");
		hs->connect_cb(hs, error_message, hs->cb_data);
		return;
	}

	hs->fd = fd;
	hs->connect_cb(hs, NULL, hs->cb_data);
}

static void _purple_http_socket_connected_ssl(gpointer _hs,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	PurpleHttpSocket *hs = _hs;

	hs->fd = hs->ssl_connection->fd;
	hs->connect_cb(hs, NULL, hs->cb_data);
}

static void _purple_http_socket_connected_ssl_error(
	PurpleSslConnection *ssl_connection, PurpleSslErrorType error,
	gpointer _hs)
{
	PurpleHttpSocket *hs = _hs;

	hs->ssl_connection = NULL;
	hs->connect_cb(hs, purple_ssl_strerror(error), hs->cb_data);
}

static gchar *
purple_http_socket_hash(const gchar *host, int port, gboolean is_ssl)
{
	return g_strdup_printf("%c:%s:%d", (is_ssl ? 'S' : 'R'), host, port);
}

static PurpleHttpSocket *
purple_http_socket_connect_new(PurpleConnection *gc, const gchar *host, int port, gboolean is_ssl, PurpleHttpSocketConnectCb cb, gpointer user_data)
{
	PurpleHttpSocket *hs = g_new0(PurpleHttpSocket, 1);
	PurpleAccount *account = NULL;

	if (gc != NULL)
		account = purple_connection_get_account(gc);

	hs->is_ssl = is_ssl;
	hs->connect_cb = cb;
	hs->cb_data = user_data;
	hs->fd = -1;

	if (is_ssl) {
		if (!purple_ssl_is_supported()) {
			g_free(hs);
			return NULL;
		}

		hs->ssl_connection = purple_ssl_connect(account,
			host, port,
			_purple_http_socket_connected_ssl,
			_purple_http_socket_connected_ssl_error, hs);
/* TODO
		purple_ssl_set_compatibility_level(hs->ssl_connection,
			PURPLE_SSL_COMPATIBILITY_SECURE);
*/
	} else {
		hs->raw_connection = purple_proxy_connect(gc, account,
			host, port,
			_purple_http_socket_connected_raw, hs);
	}

	if (hs->ssl_connection == NULL &&
		hs->raw_connection == NULL) {
		g_free(hs);
		return NULL;
	}

	if (purple_debug_is_verbose())
		purple_debug_misc("http", "new socket created: %p\n", hs);

	return hs;
}

static int
purple_http_socket_read(PurpleHttpSocket *hs, gchar *buf, size_t len)
{
	g_return_val_if_fail(hs != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);

	if (hs->is_ssl)
		return purple_ssl_read(hs->ssl_connection, buf, sizeof(buf));
	else
		return read(hs->fd, buf, sizeof(buf));
}

static int
purple_http_socket_write(PurpleHttpSocket *hs, const gchar *buf, size_t len)
{
	g_return_val_if_fail(hs != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);

	if (hs->is_ssl)
		return purple_ssl_write(hs->ssl_connection, buf, len);
	else
		return write(hs->fd, buf, len);
}

static void _purple_http_socket_watch_recv_ssl(gpointer _hs,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	PurpleHttpSocket *hs = _hs;

	g_return_if_fail(hs != NULL);

	hs->watch_cb(hs->cb_data, hs->fd, cond);
}

static void
purple_http_socket_watch(PurpleHttpSocket *hs, PurpleInputCondition cond,
	PurpleInputFunction func, gpointer user_data)
{
	g_return_if_fail(hs != NULL);

	if (hs->inpa > 0)
		purple_input_remove(hs->inpa);
	hs->inpa = 0;

	if (cond == PURPLE_INPUT_READ && hs->is_ssl) {
		hs->watch_cb = func;
		hs->cb_data = user_data;
		purple_ssl_input_add(hs->ssl_connection,
			_purple_http_socket_watch_recv_ssl, hs);
	}
	else
		hs->inpa = purple_input_add(hs->fd, cond, func, user_data);
}

static void
purple_http_socket_dontwatch(PurpleHttpSocket *hs)
{
	g_return_if_fail(hs != NULL);

	if (hs->inpa > 0)
		purple_input_remove(hs->inpa);
	hs->inpa = 0;
	if (hs->ssl_connection)
		purple_ssl_input_remove(hs->ssl_connection);
}

static void
purple_http_socket_close_free(PurpleHttpSocket *hs)
{
	if (hs == NULL)
		return;

	if (purple_debug_is_verbose())
		purple_debug_misc("http", "destroying socket: %p\n", hs);

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

	g_free(hs);
}

/*** Headers collection *******************************************************/

static PurpleHttpHeaders * purple_http_headers_new(void);
static void purple_http_headers_free(PurpleHttpHeaders *hdrs);
static void purple_http_headers_add(PurpleHttpHeaders *hdrs, const gchar *key,
	const gchar *value);
static const GList * purple_http_headers_get_all(PurpleHttpHeaders *hdrs);
static GList * purple_http_headers_get_all_by_name(
	PurpleHttpHeaders *hdrs, const gchar *key);
static const gchar * purple_http_headers_get(PurpleHttpHeaders *hdrs,
	const gchar *key);
static gboolean purple_http_headers_get_int(PurpleHttpHeaders *hdrs,
	const gchar *key, int *dst);
static gboolean purple_http_headers_match(PurpleHttpHeaders *hdrs,
	const gchar *key, const gchar *value);
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
	GList *named_values, *new_values;
	gchar *key_low;

	g_return_if_fail(hdrs != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(value != NULL);

	kvp = g_new0(PurpleKeyValuePair, 1);
	kvp->key = g_strdup(key);
	kvp->value = g_strdup(value);
	hdrs->list = g_list_append(hdrs->list, kvp);

	key_low = g_ascii_strdown(key, -1);
	named_values = g_hash_table_lookup(hdrs->by_name, key_low);
	new_values = g_list_append(named_values, kvp->value);
	if (named_values)
		g_free(key_low);
	else
		g_hash_table_insert(hdrs->by_name, key_low, new_values);
}

static void purple_http_headers_remove(PurpleHttpHeaders *hdrs,
	const gchar *key)
{
	GList *it, *curr;

	g_return_if_fail(hdrs != NULL);
	g_return_if_fail(key != NULL);

	if (!g_hash_table_remove(hdrs->by_name, key))
		return;

	/* Could be optimized to O(1). */
	it = g_list_first(hdrs->list);
	while (it)
	{
		PurpleKeyValuePair *kvp = it->data;
		curr = it;
		it = g_list_next(it);
		if (g_ascii_strcasecmp(kvp->key, key) != 0)
			continue;

		hdrs->list = g_list_delete_link(hdrs->list, curr);
		purple_http_headers_free_kvp(kvp);
	}
}

static const GList * purple_http_headers_get_all(PurpleHttpHeaders *hdrs)
{
	return hdrs->list;
}

/* return const */
static GList * purple_http_headers_get_all_by_name(
	PurpleHttpHeaders *hdrs, const gchar *key)
{
	GList *values;
	gchar *key_low;

	g_return_val_if_fail(hdrs != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	key_low = g_ascii_strdown(key, -1);
	values = g_hash_table_lookup(hdrs->by_name, key_low);
	g_free(key_low);

	return values;
}

static const gchar * purple_http_headers_get(PurpleHttpHeaders *hdrs,
	const gchar *key)
{
	const GList *values = purple_http_headers_get_all_by_name(hdrs, key);

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

static gboolean purple_http_headers_match(PurpleHttpHeaders *hdrs,
	const gchar *key, const gchar *value)
{
	const gchar *str;

	str = purple_http_headers_get(hdrs, key);
	if (str == NULL || value == NULL)
		return str == value;

	return (g_ascii_strcasecmp(str, value) == 0);
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

static void _purple_http_disconnect(PurpleHttpConnection *hc,
	gboolean is_graceful);

static void _purple_http_gen_headers(PurpleHttpConnection *hc);
static gboolean _purple_http_recv_loopbody(PurpleHttpConnection *hc, gint fd);
static void _purple_http_recv(gpointer _hc, gint fd,
	PurpleInputCondition cond);
static void _purple_http_send(gpointer _hc, gint fd, PurpleInputCondition cond);

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

	if (purple_debug_is_verbose())
		purple_debug_warning("http", "error: %s\n", hc->response->error);

	purple_http_conn_cancel(hc);
}

static void _purple_http_gen_headers(PurpleHttpConnection *hc)
{
	GString *h;
	PurpleHttpURL *url;
	const GList *hdr;
	PurpleHttpRequest *req;
	PurpleHttpHeaders *hdrs;
	gchar *request_url, *tmp_url = NULL;

	PurpleProxyInfo *proxy;
	gboolean proxy_http = FALSE;
	const gchar *proxy_username, *proxy_password;

	g_return_if_fail(hc != NULL);

	if (hc->request_header != NULL)
		return;

	req = hc->request;
	url = hc->url;
	hdrs = req->headers;
	proxy = purple_proxy_get_setup(hc->gc ?
		purple_connection_get_account(hc->gc) : NULL);

	proxy_http = (purple_proxy_info_get_type(proxy) == PURPLE_PROXY_HTTP ||
		purple_proxy_info_get_type(proxy) == PURPLE_PROXY_USE_ENVVAR);
	/* this is HTTP proxy, but used with tunelling with CONNECT */
	if (proxy_http && url->port != 80)
		proxy_http = FALSE;

	hc->request_header = h = g_string_new("");
	hc->request_header_written = 0;
	hc->request_contents_written = 0;

	if (proxy_http)
		request_url = tmp_url = purple_http_url_print(url);
	else
		request_url = url->path;

	g_string_append_printf(h, "%s %s HTTP/%s\r\n",
		req->method ? req->method : "GET",
		request_url,
		req->http11 ? "1.1" : "1.0");

	if (tmp_url)
		g_free(tmp_url);

	if (!purple_http_headers_get(hdrs, "host"))
		g_string_append_printf(h, "Host: %s\r\n", url->host);
	if (!purple_http_headers_get(hdrs, "connection")) {
		g_string_append(h, "Connection: ");
		g_string_append(h, hc->is_keepalive ?
			"Keep-Alive\r\n" : "close\r\n");
	}
	if (!purple_http_headers_get(hdrs, "accept"))
		g_string_append(h, "Accept: */*\r\n");

	if (!purple_http_headers_get(hdrs, "content-length") && (
		req->contents_length > 0 ||
		purple_http_request_is_method(req, "post")))
	{
		g_string_append_printf(h, "Content-Length: %u\r\n",
			req->contents_length);
	}

	if (proxy_http)
		g_string_append(h, "Proxy-Connection: close\r\n"); /* TEST: proxy+KeepAlive */

	proxy_username = purple_proxy_info_get_username(proxy);
	if (proxy_http && proxy_username != NULL && proxy_username[0] != '\0') {
		gchar *proxy_auth, *ntlm_type1, *tmp;
		int len;

		proxy_password = purple_proxy_info_get_password(proxy);
		if (proxy_password == NULL)
			proxy_password = "";

		tmp = g_strdup_printf("%s:%s", proxy_username, proxy_password);
		len = strlen(tmp);
		proxy_auth = purple_base64_encode((const guchar *)tmp, len);
		memset(tmp, 0, len);
		g_free(tmp);

		ntlm_type1 = purple_ntlm_gen_type1(purple_get_host_name(), "");

		g_string_append_printf(h, "Proxy-Authorization: Basic %s\r\n",
			proxy_auth);
		g_string_append_printf(h, "Proxy-Authorization: NTLM %s\r\n",
			ntlm_type1);
		g_string_append(h, "Proxy-Connection: close\r\n"); /* TEST: proxy+KeepAlive */

		memset(proxy_auth, 0, strlen(proxy_auth));
		g_free(proxy_auth);
		g_free(ntlm_type1);
	}

	hdr = purple_http_headers_get_all(hdrs);
	while (hdr) {
		PurpleKeyValuePair *kvp = hdr->data;
		hdr = g_list_next(hdr);

		g_string_append_printf(h, "%s: %s\r\n",
			kvp->key, (gchar*)kvp->value);
	}

	if (!purple_http_cookie_jar_is_empty(req->cookie_jar)) {
		gchar * cookies = purple_http_cookie_jar_gen(req->cookie_jar);
		g_string_append_printf(h, "Cookie: %s\r\n", cookies);
		g_free(cookies);
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

	if (hc->headers_got) {
		purple_debug_error("http", "Headers already got\n");
		_purple_http_error(hc, _("Error parsing HTTP"));
		return FALSE;
	}

	g_string_append_len(hc->response_buffer, buf, len);
	if (hc->response_buffer->len > PURPLE_HTTP_MAX_RECV_BUFFER_LEN) {
		purple_debug_error("http",
			"Buffer too big when parsing headers\n");
		_purple_http_error(hc, _("Error parsing HTTP"));
		return FALSE;
	}

	while ((eol = strstr(hc->response_buffer->str, "\r\n"))
		!= NULL) {
		gchar *hdrline = hc->response_buffer->str;
		int hdrline_len = eol - hdrline;

		hdrline[hdrline_len] = '\0';

		if (hdrline[0] == '\0') {
			if (!hc->main_header_got) {
				if (purple_debug_is_verbose() &&
					hc->is_keepalive)
				{
					purple_debug_misc("http", "Got keep-"
						"alive terminator from previous"
						" request\n");
				} else {
					purple_debug_warning("http", "Got empty"
						" line at the beginning - this "
						"may be a HTTP server quirk\n");
				}
			} else /* hc->main_header_got */ {
				hc->headers_got = TRUE;
				if (purple_debug_is_verbose()) {
					purple_debug_misc("http", "Got headers "
						"end\n");
				}
			}
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
				purple_debug_misc("http",
					"Got main header with code %d\n",
					hc->response->code);
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

static gboolean _purple_http_recv_body_data(PurpleHttpConnection *hc,
	const gchar *buf, int len)
{
	int current_offset = hc->length_got;

	if (hc->length_expected >= 0 &&
		len + hc->length_got > hc->length_expected)
	{
		len = hc->length_expected - hc->length_got;
	}
	if (hc->request->max_length >= 0) {
		if (hc->length_got + len > hc->request->max_length) {
			purple_debug_warning("http",
				"Maximum length exceeded, truncating\n");
			len = hc->request->max_length - hc->length_got;
			hc->length_expected = hc->request->max_length;
		}
	}
	hc->length_got += len;

	if (len == 0)
		return TRUE;

	if (hc->request->response_writer != NULL) {
		gboolean succ;
		succ = hc->request->response_writer(hc, hc->response, buf,
			current_offset, len, hc->request->response_writer_data);
		if (!succ) {
			purple_debug_error("http",
				"Cannot write using callback\n");
			_purple_http_error(hc,
				_("Error handling retrieved data"));
			return FALSE;
		}
	} else {
		if (hc->response->contents == NULL)
			hc->response->contents = g_string_new("");
		g_string_append_len(hc->response->contents, buf, len);
	}

	purple_http_conn_notify_progress_watcher(hc);
	return TRUE;
}

static gboolean _purple_http_recv_body_chunked(PurpleHttpConnection *hc,
	const gchar *buf, int len)
{
	gchar *eol, *line;
	int line_len;

	if (hc->chunks_done)
		return FALSE;
	if (!hc->response_buffer)
		hc->response_buffer = g_string_new("");

	g_string_append_len(hc->response_buffer, buf, len);
	if (hc->response_buffer->len > PURPLE_HTTP_MAX_RECV_BUFFER_LEN) {
		purple_debug_error("http",
			"Buffer too big when searching for chunk\n");
		_purple_http_error(hc, _("Error parsing HTTP"));
		return FALSE;
	}

	while (hc->response_buffer->len > 0) {
		if (hc->in_chunk) {
			int got_now = hc->response_buffer->len;
			if (hc->chunk_got + got_now > hc->chunk_length)
				got_now = hc->chunk_length - hc->chunk_got;
			hc->chunk_got += got_now;
			
			if (!_purple_http_recv_body_data(hc,
				hc->response_buffer->str, got_now))
				return FALSE;

			g_string_erase(hc->response_buffer, 0, got_now);
			hc->in_chunk = (hc->chunk_got < hc->chunk_length);

			continue;
		}

		line = hc->response_buffer->str;
		eol = strstr(line, "\r\n");
		if (eol == line) {
			g_string_erase(hc->response_buffer, 0, 2);
			line = hc->response_buffer->str;
			eol = strstr(line, "\r\n");
		}
		if (eol == NULL) {
			/* waiting for more data (unlikely, but possible) */
			if (hc->response_buffer->len > 20) {
				purple_debug_warning("http", "Chunk length not "
					"found (buffer too large)\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
				return FALSE;
			}
			return TRUE;
		}
		line_len = eol - line;

		if (1 != sscanf(line, "%x", &hc->chunk_length)) {
			if (purple_debug_is_unsafe())
				purple_debug_warning("http",
					"Chunk length not found in [%s]\n",
					line);
			else
				purple_debug_warning("http",
					"Chunk length not found\n");
			_purple_http_error(hc, _("Error parsing HTTP"));
			return FALSE;
		}
		hc->chunk_got = 0;
		hc->in_chunk = TRUE;

		if (purple_debug_is_verbose())
			purple_debug_misc("http", "Found chunk of length %d\n", hc->chunk_length);

		g_string_erase(hc->response_buffer, 0, line_len + 2);

		if (hc->chunk_length == 0) {
			hc->chunks_done = TRUE;
			hc->in_chunk = FALSE;
			return TRUE;
		}
	}

	return TRUE;
}

static gboolean _purple_http_recv_body(PurpleHttpConnection *hc,
	const gchar *buf, int len)
{
	if (hc->is_chunked)
		return _purple_http_recv_body_chunked(hc, buf, len);

	return _purple_http_recv_body_data(hc, buf, len);
}

static gboolean _purple_http_recv_loopbody(PurpleHttpConnection *hc, gint fd)
{
	int len;
	gchar buf[4096];
	gboolean got_anything;

	len = purple_http_socket_read(hc->socket, buf, sizeof(buf));
	got_anything = (len > 0);

	if (len < 0 && errno == EAGAIN)
		return FALSE;

	if (len < 0) {
		_purple_http_error(hc, _("Error reading from %s: %s"),
			hc->url->host, g_strerror(errno));
		return FALSE;
	}

	/* EOF */
	if (len == 0) {
		if (hc->request->max_length == 0) {
			/* It's definitely YHttpServer quirk. */
			purple_debug_warning("http", "Got EOF, but no data was "
				"expected (this may be a server quirk)\n");
			hc->length_expected = hc->length_got;
		}
		if (hc->length_expected >= 0 &&
			hc->length_got < hc->length_expected) {
			purple_debug_warning("http", "No more data while reading"
				" contents\n");
			_purple_http_error(hc, _("Error parsing HTTP"));
			return FALSE;
		}
		if (hc->headers_got)
			hc->length_expected = hc->length_got;
		else if (hc->length_got == 0 && hc->socket->use_count > 1) {
			purple_debug_info("http", "Keep-alive connection "
				"expired (when reading), retrying...\n");
			purple_http_conn_retry(hc);
			return FALSE;
		} else {
			if (g_ascii_strcasecmp(purple_http_headers_get(
				hc->response->headers, "Server"),
				"YHttpServer") == 0)
			{
				purple_debug_warning("http", "No more data "
					"while parsing headers (YHttpServer "
					"quirk)\n");
				hc->headers_got = TRUE;
				hc->length_expected = hc->length_got = 0;
			} else {
				purple_debug_warning("http", "No more data "
					"while parsing headers\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
				return FALSE;
			}
		}
	}

	if (!hc->headers_got && len > 0) {
		if (!_purple_http_recv_headers(hc, buf, len))
			return FALSE;
		len = 0;
		if (hc->headers_got) {
			if (!purple_http_headers_get_int(hc->response->headers,
				"Content-Length", &hc->length_expected))
				hc->length_expected = -1;
			hc->is_chunked = (purple_http_headers_match(
				hc->response->headers,
				"Transfer-Encoding", "chunked"));
		}
		if (hc->headers_got && hc->response_buffer &&
			hc->response_buffer->len > 0) {
			int buffer_len = hc->response_buffer->len;
			gchar *buffer = g_string_free(hc->response_buffer, FALSE);
			hc->response_buffer = NULL;
			_purple_http_recv_body(hc, buffer, buffer_len);
		}
		if (!hc->headers_got)
			return got_anything;
	}

	if (len > 0) {
		if (!_purple_http_recv_body(hc, buf, len))
			return FALSE;
	}

	if (hc->is_chunked && hc->chunks_done && hc->length_expected < 0)
		hc->length_expected = hc->length_got;

	if (hc->length_expected >= 0 && hc->length_got >= hc->length_expected) {
		const gchar *redirect;

		if (hc->is_chunked && !hc->chunks_done) {
			if (purple_debug_is_verbose()) {
				purple_debug_misc("http",
					"I need the terminating empty chunk\n");
			}
			return TRUE;
		}

		if (!hc->headers_got) {
			hc->response->code = 0;
			purple_debug_warning("http", "No headers got\n");
			_purple_http_error(hc, _("Error parsing HTTP"));
			return FALSE;
		}

		if (purple_debug_is_unsafe() && purple_debug_is_verbose()) {
			gchar *hdrs = purple_http_headers_dump(
				hc->response->headers);
			purple_debug_misc("http", "Got response headers: %s\n",
				hdrs);
			g_free(hdrs);
		}

		purple_http_cookie_jar_parse(hc->request->cookie_jar,
			purple_http_headers_get_all_by_name(
				hc->response->headers, "Set-Cookie"));

		if (purple_debug_is_unsafe() && purple_debug_is_verbose() &&
			!purple_http_cookie_jar_is_empty(
				hc->request->cookie_jar)) {
			gchar *cookies = purple_http_cookie_jar_dump(
				hc->request->cookie_jar);
			purple_debug_misc("http", "Cookies: %s\n", cookies);
			g_free(cookies);
		}

		if (hc->response->code == 407) {
			_purple_http_error(hc, _("Invalid proxy credentials"));
			return FALSE;
		}

		redirect = purple_http_headers_get(hc->response->headers,
			"location");
		if (redirect && (hc->request->max_redirects == -1 ||
			hc->request->max_redirects > hc->redirects_count)) {
			PurpleHttpURL *url = purple_http_url_parse(redirect);

			hc->redirects_count++;

			if (!url) {
				if (purple_debug_is_unsafe())
					purple_debug_warning("http",
						"Invalid redirect to %s\n",
						redirect);
				else
					purple_debug_warning("http",
						"Invalid redirect\n");
				_purple_http_error(hc, _("Error parsing HTTP"));
			}

			purple_http_url_relative(hc->url, url);
			purple_http_url_free(url);

			_purple_http_reconnect(hc);
			return FALSE;
		}

		_purple_http_disconnect(hc, TRUE);
		purple_http_connection_terminate(hc);
		return FALSE;
	}

	return got_anything;
}

static void _purple_http_recv(gpointer _hc, gint fd, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;

	while (_purple_http_recv_loopbody(hc, fd));
}

static void _purple_http_send_got_data(PurpleHttpConnection *hc,
	gboolean success, gboolean eof, size_t stored)
{
	int estimated_length;

	g_return_if_fail(hc != NULL);

	if (!success) {
		_purple_http_error(hc, _("Error requesting data to write"));
		return;
	}

	hc->contents_reader_requested = FALSE;
	g_string_set_size(hc->contents_reader_buffer, stored);
	if (!eof)
		return;

	estimated_length = hc->request_contents_written + stored;

	if (hc->request->contents_length != -1 &&
		hc->request->contents_length != estimated_length) {
		purple_debug_warning("http",
			"Invalid amount of data has been written\n");
	}
	hc->request->contents_length = estimated_length;
}

static void _purple_http_send(gpointer _hc, gint fd, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;
	int written, write_len;
	const gchar *write_from;
	gboolean writing_headers;

	/* Waiting for data. This could be written more efficiently, by removing
	 * (and later, adding) hs->inpa. */
	if (hc->contents_reader_requested)
		return;

	_purple_http_gen_headers(hc);

	writing_headers =
		(hc->request_header_written < hc->request_header->len);
	if (writing_headers) {
		write_from = hc->request_header->str +
			hc->request_header_written;
		write_len = hc->request_header->len -
			hc->request_header_written;
	} else if (hc->request->contents_reader) {
		if (hc->contents_reader_requested)
			return; /* waiting for data */
		if (!hc->contents_reader_buffer)
			hc->contents_reader_buffer = g_string_new("");
		if (hc->contents_reader_buffer->len == 0) {
			hc->contents_reader_requested = TRUE;
			g_string_set_size(hc->contents_reader_buffer,
				PURPLE_HTTP_MAX_READ_BUFFER_LEN);
			hc->request->contents_reader(hc,
				hc->contents_reader_buffer->str,
				hc->request_contents_written,
				PURPLE_HTTP_MAX_READ_BUFFER_LEN,
				hc->request->contents_reader_data,
				_purple_http_send_got_data);
			return;
		}
		write_from = hc->contents_reader_buffer->str;
		write_len = hc->contents_reader_buffer->len;
	} else {
		write_from = hc->request->contents +
			hc->request_contents_written;
		write_len = hc->request->contents_length -
			hc->request_contents_written;
	}

	if (write_len == 0) {
		purple_debug_warning("http", "Nothing to write\n");
		written = 0;
	} else {
		written = purple_http_socket_write(hc->socket, write_from,
			write_len);
	}

	if (written < 0 && errno == EAGAIN)
		return;

	if (written < 0) {
		if (hc->request_header_written == 0 &&
			hc->socket->use_count > 1)
		{
			purple_debug_info("http", "Keep-alive connection "
				"expired (when writing), retrying...\n");
			purple_http_conn_retry(hc);
			return;
		}

		_purple_http_error(hc, _("Error writing to %s: %s"),
			hc->url->host, g_strerror(errno));
		return;
	}

	if (writing_headers) {
		hc->request_header_written += written;
		purple_http_conn_notify_progress_watcher(hc);
		if (hc->request_header_written < hc->request_header->len)
			return;
		if (hc->request->contents_length > 0)
			return;
	} else {
		hc->request_contents_written += written;
		purple_http_conn_notify_progress_watcher(hc);
		if (hc->contents_reader_buffer)
			g_string_erase(hc->contents_reader_buffer, 0, written);
		if (hc->request_contents_written < hc->request->contents_length)
			return;
	}

	/* request is completely written, let's read the response */
	hc->is_reading = TRUE;
	purple_http_socket_watch(hc->socket, PURPLE_INPUT_READ,
		_purple_http_recv, hc);
}

static void _purple_http_disconnect(PurpleHttpConnection *hc,
	gboolean is_graceful)
{
	g_return_if_fail(hc != NULL);

	if (hc->request_header)
		g_string_free(hc->request_header, TRUE);
	hc->request_header = NULL;

	if (hc->response_buffer)
		g_string_free(hc->response_buffer, TRUE);
	hc->response_buffer = NULL;

	if (hc->socket_request)
		purple_http_keepalive_pool_request_cancel(hc->socket_request);
	else {
		purple_http_keepalive_pool_release(hc->socket, !is_graceful);
		hc->socket = NULL;
	}
}

static void  _purple_http_connected(PurpleHttpSocket *hs, const gchar *error, gpointer _hc)
{
	PurpleHttpConnection *hc = _hc;

	hc->socket_request = NULL;
	hc->socket = hs;

	if (error != NULL) {
		_purple_http_error(hc, _("Unable to connect to %s: %s"),
			hc->url->host, error);
		return;
	}

	purple_http_socket_watch(hs, PURPLE_INPUT_WRITE, _purple_http_send, hc);
}

static gboolean _purple_http_reconnect(PurpleHttpConnection *hc)
{
	PurpleHttpURL *url;
	gboolean is_ssl = FALSE;

	g_return_val_if_fail(hc != NULL, FALSE);
	g_return_val_if_fail(hc->url != NULL, FALSE);

	_purple_http_disconnect(hc, TRUE);

	if (purple_debug_is_verbose()) {
		if (purple_debug_is_unsafe()) {
			gchar *url = purple_http_url_print(hc->url);
			purple_debug_misc("http", "Connecting to %s...\n", url);
			g_free(url);
		} else
			purple_debug_misc("http", "Connecting to %s...\n",
				hc->url->host);
	}

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

	if (is_ssl && !purple_ssl_is_supported()) {
		_purple_http_error(hc, _("Unable to connect to %s: %s"),
			url->host, _("Server requires TLS/SSL, "
			"but no TLS/SSL support was found."));
		return FALSE;
	}

	if (hc->request->keepalive_pool != NULL) {
		hc->socket_request = purple_http_keepalive_pool_request(
			hc->request->keepalive_pool, hc->gc, url->host,
			url->port, is_ssl, _purple_http_connected, hc);
	} else {
		hc->socket = purple_http_socket_connect_new(hc->gc, url->host,
			url->port, is_ssl, _purple_http_connected, hc);
	}

	if (hc->socket_request == NULL && hc->socket == NULL) {
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
	hc->is_chunked = FALSE;
	hc->in_chunk = FALSE;
	hc->chunks_done = FALSE;

	purple_http_conn_notify_progress_watcher(hc);

	return TRUE;
}

/*** Performing HTTP requests *************************************************/

static gboolean purple_http_request_timeout(gpointer _hc)
{
	PurpleHttpConnection *hc = _hc;

	purple_debug_warning("http", "Timeout reached for request %p\n", hc);

	purple_http_conn_cancel(hc);

	return FALSE;
}

PurpleHttpConnection * purple_http_get(PurpleConnection *gc,
	PurpleHttpCallback callback, gpointer user_data, const gchar *url)
{
	PurpleHttpRequest *request;
	PurpleHttpConnection *hc;

	g_return_val_if_fail(url != NULL, NULL);

	request = purple_http_request_new(url);
	hc = purple_http_request(gc, request, callback, user_data);
	purple_http_request_unref(request);

	return hc;
}

PurpleHttpConnection * purple_http_get_printf(PurpleConnection *gc,
	PurpleHttpCallback callback, gpointer user_data,
	const gchar *format, ...)
{
	va_list args;
	gchar *value;
	PurpleHttpConnection *ret;

	g_return_val_if_fail(format != NULL, NULL);

	va_start(args, format);
	value = g_strdup_vprintf(format, args);
	va_end(args);

	ret = purple_http_get(gc, callback, user_data, value);
	g_free(value);

	return ret;
}

PurpleHttpConnection * purple_http_request(PurpleConnection *gc,
	PurpleHttpRequest *request, PurpleHttpCallback callback,
	gpointer user_data)
{
	PurpleHttpConnection *hc;

	g_return_val_if_fail(request != NULL, NULL);

	if (request->url == NULL) {
		purple_debug_error("http", "Cannot perform new request - "
			"URL is not set\n");
		return NULL;
	}

	if (g_hash_table_lookup(purple_http_cancelling_gc, gc)) {
		purple_debug_warning("http", "Cannot perform another HTTP "
			"request while cancelling all related with this "
			"PurpleConnection\n");
		return NULL;
	}

	hc = purple_http_connection_new(request, gc);
	hc->callback = callback;
	hc->user_data = user_data;

	hc->url = purple_http_url_parse(request->url);

	if (purple_debug_is_unsafe())
		purple_debug_misc("http", "Performing new request %p for %s.\n",
			hc, request->url);
	else
		purple_debug_misc("http", "Performing new request %p to %s.\n",
			hc, hc->url ? hc->url->host : NULL);

	if (!hc->url || hc->url->host == NULL || hc->url->host[0] == '\0') {
		purple_debug_error("http", "Invalid URL requested.\n");
		purple_http_connection_terminate(hc);
		return NULL;
	}

	_purple_http_reconnect(hc);

	hc->timeout_handle = purple_timeout_add_seconds(request->timeout,
		purple_http_request_timeout, hc);

	return hc;
}

/*** HTTP connection API ******************************************************/

static void purple_http_connection_free(PurpleHttpConnection *hc);
static gboolean purple_http_conn_notify_progress_watcher_timeout(gpointer _hc);

static PurpleHttpConnection * purple_http_connection_new(
	PurpleHttpRequest *request, PurpleConnection *gc)
{
	PurpleHttpConnection *hc = g_new0(PurpleHttpConnection, 1);

	hc->request = request;
	purple_http_request_ref(request);
	hc->response = purple_http_response_new();
	hc->is_keepalive = (request->keepalive_pool != NULL);

	hc->link_global = purple_http_hc_list =
		g_list_prepend(purple_http_hc_list, hc);
	g_hash_table_insert(purple_http_hc_by_ptr, hc, hc->link_global);
	if (gc) {
		GList *gc_list = g_hash_table_lookup(purple_http_hc_by_gc, gc);
		g_hash_table_steal(purple_http_hc_by_gc, gc);
		hc->link_gc = gc_list = g_list_prepend(gc_list, hc);
		g_hash_table_insert(purple_http_hc_by_gc, gc, gc_list);
		hc->gc = gc;
	}

	return hc;
}

static void purple_http_connection_free(PurpleHttpConnection *hc)
{
	if (hc->timeout_handle)
		purple_timeout_remove(hc->timeout_handle);
	if (hc->watcher_delayed_handle)
		purple_timeout_remove(hc->watcher_delayed_handle);

	if (hc->connection_set != NULL)
		purple_http_connection_set_remove(hc->connection_set, hc);

	purple_http_url_free(hc->url);
	purple_http_request_unref(hc->request);
	purple_http_response_free(hc->response);

	if (hc->contents_reader_buffer)
		g_string_free(hc->contents_reader_buffer, TRUE);

	if (hc->request_header)
		g_string_free(hc->request_header, TRUE);

	purple_http_hc_list = g_list_delete_link(purple_http_hc_list,
		hc->link_global);
	g_hash_table_remove(purple_http_hc_by_ptr, hc);
	if (hc->gc) {
		GList *gc_list, *gc_list_new;
		gc_list = g_hash_table_lookup(purple_http_hc_by_gc, hc->gc);
		g_assert(gc_list != NULL);

		gc_list_new = g_list_delete_link(gc_list, hc->link_gc);
		if (gc_list != gc_list_new) {
			g_hash_table_steal(purple_http_hc_by_gc, hc->gc);
			if (gc_list_new)
				g_hash_table_insert(purple_http_hc_by_gc,
					hc->gc, gc_list_new);
		}
	}

	g_free(hc);
}

/* call callback and do the cleanup */
static void purple_http_connection_terminate(PurpleHttpConnection *hc)
{
	g_return_if_fail(hc != NULL);

	purple_debug_misc("http", "Request %p performed %s.\n", hc,
		purple_http_response_is_successful(hc->response) ?
		"successfully" : "without success");

	if (hc->callback)
		hc->callback(hc, hc->response, hc->user_data);

	purple_http_connection_free(hc);
}

void purple_http_conn_cancel(PurpleHttpConnection *http_conn)
{
	if (http_conn == NULL)
		return;

	if (http_conn->is_cancelling)
		return;
	http_conn->is_cancelling = TRUE;

	if (purple_debug_is_verbose()) {
		purple_debug_misc("http", "Cancelling connection %p...\n",
			http_conn);
	}

	http_conn->response->code = 0;
	_purple_http_disconnect(http_conn, FALSE);
	purple_http_connection_terminate(http_conn);
}

static void
purple_http_conn_retry(PurpleHttpConnection *http_conn)
{
	if (http_conn == NULL)
		return;

	purple_debug_info("http", "Retrying connection %p...\n", http_conn);

	http_conn->response->code = 0;
	_purple_http_disconnect(http_conn, FALSE);
	_purple_http_reconnect(http_conn);
}

void purple_http_conn_cancel_all(PurpleConnection *gc)
{
	GList *gc_list;

	if (purple_debug_is_verbose()) {
		purple_debug_misc("http", "Cancelling all running HTTP "
			"connections\n");
	}

	gc_list = g_hash_table_lookup(purple_http_hc_by_gc, gc);

	g_hash_table_insert(purple_http_cancelling_gc, gc, GINT_TO_POINTER(TRUE));

	while (gc_list) {
		PurpleHttpConnection *hc = gc_list->data;
		gc_list = g_list_next(gc_list);
		purple_http_conn_cancel(hc);
	}

	g_hash_table_remove(purple_http_cancelling_gc, gc);

	if (NULL != g_hash_table_lookup(purple_http_hc_by_gc, gc))
		purple_debug_fatal("http", "Couldn't cancel all connections "
			"related to gc=%p (it shouldn't happen)\n", gc);
}

gboolean purple_http_conn_is_running(PurpleHttpConnection *http_conn)
{
	if (http_conn == NULL)
		return FALSE;
	return (NULL != g_hash_table_lookup(purple_http_hc_by_ptr, http_conn));
}

PurpleHttpRequest * purple_http_conn_get_request(PurpleHttpConnection *http_conn)
{
	g_return_val_if_fail(http_conn != NULL, NULL);

	return http_conn->request;
}

PurpleHttpCookieJar * purple_http_conn_get_cookie_jar(
	PurpleHttpConnection *http_conn)
{
	return purple_http_request_get_cookie_jar(purple_http_conn_get_request(
		http_conn));
}

PurpleConnection * purple_http_conn_get_purple_connection(
	PurpleHttpConnection *http_conn)
{
	g_return_val_if_fail(http_conn != NULL, NULL);

	return http_conn->gc;
}

void purple_http_conn_set_progress_watcher(PurpleHttpConnection *http_conn,
	PurpleHttpProgressWatcher watcher, gpointer user_data,
	gint interval_threshold)
{
	g_return_if_fail(http_conn != NULL);

	if (interval_threshold < 0) {
		interval_threshold =
			PURPLE_HTTP_PROGRESS_WATCHER_DEFAULT_INTERVAL;
	}

	http_conn->watcher = watcher;
	http_conn->watcher_user_data = user_data;
	http_conn->watcher_interval_threshold = interval_threshold;
}

static void purple_http_conn_notify_progress_watcher(
	PurpleHttpConnection *hc)
{
	gint64 now;
	gboolean reading_state;
	int processed, total;

	g_return_if_fail(hc != NULL);

	if (hc->watcher == NULL)
		return;

	reading_state = hc->is_reading;
	if (reading_state) {
		total = hc->length_expected;
		processed = hc->length_got;
	} else {
		total = hc->request->contents_length;
		processed = hc->request_contents_written;
		if (total == 0)
			total = -1;
	}
	if (total != -1 && total < processed) {
		purple_debug_warning("http", "Processed too much\n");
		total = processed;
	}

	now = g_get_monotonic_time();
	if (hc->watcher_last_call + hc->watcher_interval_threshold
		> now && processed != total) {
		if (hc->watcher_delayed_handle)
			return;
		hc->watcher_delayed_handle = purple_timeout_add_seconds(
			1 + hc->watcher_interval_threshold / 1000000,
			purple_http_conn_notify_progress_watcher_timeout, hc);
		return;
	}

	if (hc->watcher_delayed_handle)
		purple_timeout_remove(hc->watcher_delayed_handle);
	hc->watcher_delayed_handle = 0;

	hc->watcher_last_call = now;
	hc->watcher(hc, reading_state, processed, total, hc->watcher_user_data);
}

static gboolean purple_http_conn_notify_progress_watcher_timeout(gpointer _hc)
{
	PurpleHttpConnection *hc = _hc;

	purple_http_conn_notify_progress_watcher(hc);

	return FALSE;
}

/*** Cookie jar API ***********************************************************/

static PurpleHttpCookie * purple_http_cookie_new(const gchar *value);
void purple_http_cookie_free(PurpleHttpCookie *cookie);

static void purple_http_cookie_jar_set_ext(PurpleHttpCookieJar *cookie_jar,
	const gchar *name, const gchar *value, time_t expires);

static PurpleHttpCookie * purple_http_cookie_new(const gchar *value)
{
	PurpleHttpCookie *cookie = g_new0(PurpleHttpCookie, 1);

	cookie->value = g_strdup(value);
	cookie->expires = -1;

	return cookie;
}

void purple_http_cookie_free(PurpleHttpCookie *cookie)
{
	g_free(cookie->value);
	g_free(cookie);
}

void purple_http_cookie_jar_free(PurpleHttpCookieJar *cookie_jar);

PurpleHttpCookieJar * purple_http_cookie_jar_new(void)
{
	PurpleHttpCookieJar *cjar = g_new0(PurpleHttpCookieJar, 1);

	cjar->ref_count = 1;
	cjar->tab = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
		(GDestroyNotify)purple_http_cookie_free);

	return cjar;
}

void purple_http_cookie_jar_free(PurpleHttpCookieJar *cookie_jar)
{
	g_hash_table_destroy(cookie_jar->tab);
	g_free(cookie_jar);
}

void purple_http_cookie_jar_ref(PurpleHttpCookieJar *cookie_jar)
{
	g_return_if_fail(cookie_jar != NULL);

	cookie_jar->ref_count++;
}

PurpleHttpCookieJar * purple_http_cookie_jar_unref(
	PurpleHttpCookieJar *cookie_jar)
{
	if (cookie_jar == NULL)
		return NULL;

	g_return_val_if_fail(cookie_jar->ref_count > 0, NULL);

	cookie_jar->ref_count--;
	if (cookie_jar->ref_count > 0)
		return cookie_jar;

	purple_http_cookie_jar_free(cookie_jar);
	return NULL;
}

static void purple_http_cookie_jar_parse(PurpleHttpCookieJar *cookie_jar,
	GList *values)
{
	values = g_list_first(values);
	while (values) {
		const gchar *cookie = values->data;
		const gchar *eqsign, *semicolon;
		gchar *name, *value;
		time_t expires = -1;
		values = g_list_next(values);

		eqsign = strchr(cookie, '=');
		semicolon = strchr(cookie, ';');

		if (eqsign == NULL || eqsign == cookie ||
			(semicolon != NULL && semicolon < eqsign)) {
			if (purple_debug_is_unsafe())
				purple_debug_warning("http",
					"Invalid cookie: [%s]\n", cookie);
			else
				purple_debug_warning("http", "Invalid cookie.");
		}

		name = g_strndup(cookie, eqsign - cookie);
		eqsign++;
		if (semicolon != NULL)
			value = g_strndup(eqsign, semicolon - eqsign);
		else
			value = g_strdup(eqsign);

		if (semicolon != NULL) {
			GMatchInfo *match_info;
			GRegex *re_expires = g_regex_new(
				"expires=([a-z0-9, :]+)",
				G_REGEX_OPTIMIZE | G_REGEX_CASELESS,
				G_REGEX_MATCH_NOTEMPTY, NULL);

			g_regex_match(re_expires, semicolon, 0, &match_info);
			if (g_match_info_matches(match_info)) {
				gchar *expire_date =
					g_match_info_fetch(match_info, 1);
				expires = purple_http_rfc1123_to_time(
					expire_date);
				g_free(expire_date);
			}
			g_match_info_free(match_info);

			g_regex_unref(re_expires);
		}

		purple_http_cookie_jar_set_ext(cookie_jar, name, value, expires);

		g_free(name);
		g_free(value);
	}
}

static gchar * purple_http_cookie_jar_gen(PurpleHttpCookieJar *cookie_jar)
{
	GHashTableIter it;
	gchar *key;
	PurpleHttpCookie *cookie;
	GString *str;
	time_t now = time(NULL);

	g_return_val_if_fail(cookie_jar != NULL, NULL);

	str = g_string_new("");

	g_hash_table_iter_init(&it, cookie_jar->tab);
	while (g_hash_table_iter_next(&it, (gpointer*)&key,
		(gpointer*)&cookie)) {
		if (cookie->expires != -1 && cookie->expires <= now)
			continue;
		g_string_append_printf(str, "%s=%s; ", key, cookie->value);
	}

	if (str->len > 0)
		g_string_truncate(str, str->len - 2);
	return g_string_free(str, FALSE);
}

void purple_http_cookie_jar_set(PurpleHttpCookieJar *cookie_jar,
	const gchar *name, const gchar *value)
{
	purple_http_cookie_jar_set_ext(cookie_jar, name, value, -1);
}

static void purple_http_cookie_jar_set_ext(PurpleHttpCookieJar *cookie_jar,
	const gchar *name, const gchar *value, time_t expires)
{
	g_return_if_fail(cookie_jar != NULL);
	g_return_if_fail(name != NULL);

	if (expires != -1 && time(NULL) >= expires)
		value = NULL;

	if (value != NULL) {
		PurpleHttpCookie *cookie = purple_http_cookie_new(value);
		cookie->expires = expires;
		g_hash_table_insert(cookie_jar->tab, g_strdup(name), cookie);
	} else
		g_hash_table_remove(cookie_jar->tab, name);
}

const gchar * purple_http_cookie_jar_get(PurpleHttpCookieJar *cookie_jar,
	const gchar *name)
{
	PurpleHttpCookie *cookie;

	g_return_val_if_fail(cookie_jar != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	cookie = g_hash_table_lookup(cookie_jar->tab, name);
	if (!cookie)
		return NULL;

	return cookie->value;
}

gchar * purple_http_cookie_jar_dump(PurpleHttpCookieJar *cjar)
{
	GHashTableIter it;
	gchar *key;
	PurpleHttpCookie *cookie;
	GString *str = g_string_new("");

	g_hash_table_iter_init(&it, cjar->tab);
	while (g_hash_table_iter_next(&it, (gpointer*)&key, (gpointer*)&cookie))
		g_string_append_printf(str, "%s: %s (expires: %" G_GINT64_FORMAT
		")\n", key, cookie->value, (gint64)cookie->expires);

	if (str->len > 0)
		g_string_truncate(str, str->len - 1);
	return g_string_free(str, FALSE);
}

gboolean purple_http_cookie_jar_is_empty(PurpleHttpCookieJar *cookie_jar)
{
	g_return_val_if_fail(cookie_jar != NULL, TRUE);

	return g_hash_table_size(cookie_jar->tab) == 0;
}

/*** HTTP Keep-Alive pool API *************************************************/

static void
purple_http_keepalive_host_process_queue(PurpleHttpKeepaliveHost *host);

static void
purple_http_keepalive_host_free(gpointer _host)
{
	PurpleHttpKeepaliveHost *host = _host;

	if (host->process_queue_timeout > 0) {
		purple_timeout_remove(host->process_queue_timeout);
		host->process_queue_timeout = 0;
	}

	g_free(host->host);

	g_slist_free_full(host->queue,
		(GDestroyNotify)purple_http_keepalive_pool_request_cancel);
	g_slist_free_full(host->sockets,
		(GDestroyNotify)purple_http_socket_close_free);

	g_free(host);
}

PurpleHttpKeepalivePool *
purple_http_keepalive_pool_new(void)
{
	PurpleHttpKeepalivePool *pool = g_new0(PurpleHttpKeepalivePool, 1);

	pool->ref_count = 1;
	pool->by_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
		purple_http_keepalive_host_free);

	return pool;
}

static void
purple_http_keepalive_pool_free(PurpleHttpKeepalivePool *pool)
{
	g_return_if_fail(pool != NULL);

	if (pool->is_destroying)
		return;
	pool->is_destroying = TRUE;
	g_hash_table_destroy(pool->by_hash);
	g_free(pool);
}

void
purple_http_keepalive_pool_ref(PurpleHttpKeepalivePool *pool)
{
	g_return_if_fail(pool != NULL);

	pool->ref_count++;
}

PurpleHttpKeepalivePool *
purple_http_keepalive_pool_unref(PurpleHttpKeepalivePool *pool)
{
	if (pool == NULL)
		return NULL;

	g_return_val_if_fail(pool->ref_count > 0, NULL);

	pool->ref_count--;
	if (pool->ref_count > 0)
		return pool;

	purple_http_keepalive_pool_free(pool);
	return NULL;
}

static PurpleHttpKeepaliveRequest *
purple_http_keepalive_pool_request(PurpleHttpKeepalivePool *pool,
	PurpleConnection *gc, const gchar *host, int port, gboolean is_ssl,
	PurpleHttpSocketConnectCb cb, gpointer user_data)
{
	PurpleHttpKeepaliveRequest *req;
	PurpleHttpKeepaliveHost *kahost;
	gchar *hash;

	g_return_val_if_fail(pool != NULL, NULL);
	g_return_val_if_fail(host != NULL, NULL);

	if (pool->is_destroying) {
		purple_debug_error("http", "pool is destroying\n");
		return NULL;
	}

	hash = purple_http_socket_hash(host, port, is_ssl);
	kahost = g_hash_table_lookup(pool->by_hash, hash);

	if (kahost == NULL) {
		kahost = g_new0(PurpleHttpKeepaliveHost, 1);
		kahost->pool = pool;
		kahost->host = g_strdup(host);
		kahost->port = port;
		kahost->is_ssl = is_ssl;

		g_hash_table_insert(pool->by_hash, g_strdup(hash), kahost);
	}

	g_free(hash);

	req = g_new0(PurpleHttpKeepaliveRequest, 1);
	req->gc = gc;
	req->cb = cb;
	req->user_data = user_data;
	req->host = kahost;

	kahost->queue = g_slist_append(kahost->queue, req);

	purple_http_keepalive_host_process_queue(kahost);

	return req;
}

static void
_purple_http_keepalive_socket_connected(PurpleHttpSocket *hs,
	const gchar *error, gpointer _req)
{
	PurpleHttpKeepaliveRequest *req = _req;

	if (hs != NULL)
		hs->use_count++;

	req->cb(hs, error, req->user_data);
	g_free(req);
}

static gboolean
_purple_http_keepalive_host_process_queue_cb(gpointer _host)
{
	PurpleHttpKeepaliveRequest *req;
	PurpleHttpKeepaliveHost *host = _host;
	PurpleHttpSocket *hs = NULL;
	GSList *it;
	int sockets_count;

	g_return_val_if_fail(host != NULL, FALSE);

	host->process_queue_timeout = 0;

	if (host->queue == NULL)
		return FALSE;

	sockets_count = 0;
	it = host->sockets;
	while (it != NULL) {
		PurpleHttpSocket *hs_current = it->data;

		sockets_count++;

		if (!hs_current->is_busy) {
			hs = hs_current;
			break;
		}

		it = g_slist_next(it);
	}

	/* There are no free sockets and we cannot create another one. */
	if (hs == NULL && sockets_count >= host->pool->limit_per_host &&
		host->pool->limit_per_host > 0)
	{
		return FALSE;
	}

	req = host->queue->data;
	host->queue = g_slist_remove(host->queue, req);

	if (hs != NULL) {
		if (purple_debug_is_verbose()) {
			purple_debug_misc("http", "locking a (previously used) "
				"socket: %p\n", hs);
		}

		hs->is_busy = TRUE;
		hs->use_count++;

		req->cb(hs, NULL, req->user_data);
		g_free(req);

		return TRUE; /* run again */
	}

	hs = purple_http_socket_connect_new(req->gc, req->host->host,
		req->host->port, req->host->is_ssl,
		_purple_http_keepalive_socket_connected, req);
	req->hs = hs;
	hs->is_busy = TRUE;
	hs->host = host;

	if (purple_debug_is_verbose())
		purple_debug_misc("http", "locking a (new) socket: %p\n", hs);

	host->sockets = g_slist_append(host->sockets, hs);

	return FALSE;
}

static void
purple_http_keepalive_host_process_queue(PurpleHttpKeepaliveHost *host)
{
	g_return_if_fail(host != NULL);

	if (host->process_queue_timeout > 0)
		return;

	host->process_queue_timeout = purple_timeout_add(0,
		_purple_http_keepalive_host_process_queue_cb, host);
}

static void
purple_http_keepalive_pool_request_cancel(PurpleHttpKeepaliveRequest *req)
{
	if (req == NULL)
		return;

	if (req->host != NULL)
		req->host->queue = g_slist_remove(req->host->queue, req);

	if (req->hs != NULL) {
		req->host->sockets = g_slist_remove(req->host->sockets,
			req->hs);
		purple_http_socket_close_free(req->hs);
		/* req should already be free'd here */
	} else {
		req->cb(req->hs, _("Cancelled"), req->user_data);
		g_free(req);
	}
}

static void
purple_http_keepalive_pool_release(PurpleHttpSocket *hs, gboolean invalidate)
{
	PurpleHttpKeepaliveHost *host;

	if (hs == NULL)
		return;

	if (purple_debug_is_verbose())
		purple_debug_misc("http", "releasing a socket: %p\n", hs);

	purple_http_socket_dontwatch(hs);
	hs->is_busy = FALSE;
	host = hs->host;

	if (host == NULL) {
		purple_http_socket_close_free(hs);
		return;
	}

	if (invalidate) {
		host->sockets = g_slist_remove(host->sockets, hs);
		purple_http_socket_close_free(hs);
	}

	purple_http_keepalive_host_process_queue(host);
}

void
purple_http_keepalive_pool_set_limit_per_host(PurpleHttpKeepalivePool *pool,
	guint limit)
{
	g_return_if_fail(pool != NULL);

	pool->limit_per_host = limit;
}

guint
purple_http_keepalive_pool_get_limit_per_host(PurpleHttpKeepalivePool *pool)
{
	g_return_val_if_fail(pool != NULL, 0);

	return pool->limit_per_host;
}

/*** HTTP connection set API **************************************************/

PurpleHttpConnectionSet *
purple_http_connection_set_new(void)
{
	PurpleHttpConnectionSet *set;

	set = g_new0(PurpleHttpConnectionSet, 1);
	set->connections = g_hash_table_new(g_direct_hash, g_direct_equal);

	return set;
}

void
purple_http_connection_set_destroy(PurpleHttpConnectionSet *set)
{
	if (set == NULL)
		return;

	set->is_destroying = TRUE;

	while (TRUE) {
		GHashTableIter iter;
		PurpleHttpConnection *http_conn;

		g_hash_table_iter_init(&iter, set->connections);
		if (!g_hash_table_iter_next(&iter, (gpointer*)&http_conn, NULL))
			break;

		purple_http_conn_cancel(http_conn);
	}

	g_hash_table_destroy(set->connections);
	g_free(set);
}

void
purple_http_connection_set_add(PurpleHttpConnectionSet *set,
	PurpleHttpConnection *http_conn)
{
	if (set->is_destroying)
		return;
	if (http_conn->connection_set == set)
		return;
	if (http_conn->connection_set != NULL) {
		purple_http_connection_set_remove(http_conn->connection_set,
			http_conn);
	}
	g_hash_table_insert(set->connections, http_conn, (gpointer)TRUE);
	http_conn->connection_set = set;
}

static void
purple_http_connection_set_remove(PurpleHttpConnectionSet *set,
	PurpleHttpConnection *http_conn)
{
	g_hash_table_remove(set->connections, http_conn);
	if (http_conn->connection_set == set)
		http_conn->connection_set = NULL;
}

/*** Request API **************************************************************/

static void purple_http_request_free(PurpleHttpRequest *request);

PurpleHttpRequest * purple_http_request_new(const gchar *url)
{
	PurpleHttpRequest *request;

	request = g_new0(PurpleHttpRequest, 1);

	request->ref_count = 1;
	request->url = g_strdup(url);
	request->headers = purple_http_headers_new();
	request->cookie_jar = purple_http_cookie_jar_new();
	request->keepalive_pool = purple_http_keepalive_pool_new();

	request->timeout = PURPLE_HTTP_REQUEST_DEFAULT_TIMEOUT;
	request->max_redirects = PURPLE_HTTP_REQUEST_DEFAULT_MAX_REDIRECTS;
	request->http11 = TRUE;
	request->max_length = PURPLE_HTTP_REQUEST_DEFAULT_MAX_LENGTH;

	return request;
}

static void purple_http_request_free(PurpleHttpRequest *request)
{
	purple_http_headers_free(request->headers);
	purple_http_cookie_jar_unref(request->cookie_jar);
	purple_http_keepalive_pool_unref(request->keepalive_pool);
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

void purple_http_request_set_url(PurpleHttpRequest *request, const gchar *url)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(url != NULL);

	g_free(request->url);
	request->url = g_strdup(url);
}

void purple_http_request_set_url_printf(PurpleHttpRequest *request,
	const gchar *format, ...)
{
	va_list args;
	gchar *value;

	g_return_if_fail(request != NULL);
	g_return_if_fail(format != NULL);

	va_start(args, format);
	value = g_strdup_vprintf(format, args);
	va_end(args);

	purple_http_request_set_url(request, value);
	g_free(value);
}

const gchar * purple_http_request_get_url(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, NULL);

	return request->url;
}

void purple_http_request_set_method(PurpleHttpRequest *request, const gchar *method)
{
	g_return_if_fail(request != NULL);

	g_free(request->method);
	request->method = g_strdup(method);
}

const gchar * purple_http_request_get_method(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, NULL);

	return request->method;
}

static gboolean purple_http_request_is_method(PurpleHttpRequest *request,
	const gchar *method)
{
	const gchar *rmethod;

	g_return_val_if_fail(request != NULL, FALSE);
	g_return_val_if_fail(method != NULL, FALSE);

	rmethod = purple_http_request_get_method(request);
	if (rmethod == NULL)
		return (g_ascii_strcasecmp(method, "get") == 0);
	return (g_ascii_strcasecmp(method, rmethod) == 0);
}

void
purple_http_request_set_keepalive_pool(PurpleHttpRequest *request,
	PurpleHttpKeepalivePool *pool)
{
	g_return_if_fail(request != NULL);

	if (pool != NULL)
		purple_http_keepalive_pool_ref(pool);

	if (request->keepalive_pool != NULL) {
		purple_http_keepalive_pool_unref(request->keepalive_pool);
		request->keepalive_pool = NULL;
	}

	if (pool != NULL)
		request->keepalive_pool = pool;
}

PurpleHttpKeepalivePool *
purple_http_request_get_keepalive_pool(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, FALSE);

	return request->keepalive_pool;
}

void purple_http_request_set_contents(PurpleHttpRequest *request,
	const gchar *contents, int length)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(length >= -1);

	request->contents_reader = NULL;
	request->contents_reader_data = NULL;

	g_free(request->contents);
	if (contents == NULL || length == 0) {
		request->contents = NULL;
		request->contents_length = 0;
		return;
	}

	if (length == -1)
		length = strlen(contents);
	request->contents = g_memdup(contents, length);
	request->contents_length = length;
}

void purple_http_request_set_contents_reader(PurpleHttpRequest *request,
	PurpleHttpContentReader reader, int contents_length, gpointer user_data)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(reader != NULL);
	g_return_if_fail(contents_length >= -1);

	g_free(request->contents);
	request->contents = NULL;
	request->contents_length = contents_length;
	request->contents_reader = reader;
	request->contents_reader_data = user_data;
}

void purple_http_request_set_response_writer(PurpleHttpRequest *request,
	PurpleHttpContentWriter writer, gpointer user_data)
{
	g_return_if_fail(request != NULL);

	if (writer == NULL)
		user_data = NULL;
	request->response_writer = writer;
	request->response_writer_data = user_data;
}

void purple_http_request_set_timeout(PurpleHttpRequest *request, int timeout)
{
	g_return_if_fail(request != NULL);

	if (timeout < -1)
		timeout = -1;

	request->timeout = timeout;
}

int purple_http_request_get_timeout(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, -1);

	return request->timeout;
}

void purple_http_request_set_max_redirects(PurpleHttpRequest *request,
	int max_redirects)
{
	g_return_if_fail(request != NULL);

	if (max_redirects < -1)
		max_redirects = -1;

	request->max_redirects = max_redirects;
}

int purple_http_request_get_max_redirects(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, -1);

	return request->max_redirects;
}

void purple_http_request_set_cookie_jar(PurpleHttpRequest *request,
	PurpleHttpCookieJar *cookie_jar)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(cookie_jar != NULL);

	purple_http_cookie_jar_ref(cookie_jar);
	purple_http_cookie_jar_unref(request->cookie_jar);
	request->cookie_jar = cookie_jar;
}

PurpleHttpCookieJar * purple_http_request_get_cookie_jar(
	PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, NULL);

	return request->cookie_jar;
}

void purple_http_request_set_http11(PurpleHttpRequest *request, gboolean http11)
{
	g_return_if_fail(request != NULL);

	request->http11 = http11;
}

gboolean purple_http_request_is_http11(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, FALSE);

	return request->http11;
}

void purple_http_request_set_max_len(PurpleHttpRequest *request, int max_len)
{
	g_return_if_fail(request != NULL);

	if (max_len < -1)
		max_len = -1;

	request->max_length = max_len;
}

int purple_http_request_get_max_len(PurpleHttpRequest *request)
{
	g_return_val_if_fail(request != NULL, -1);

	return request->max_length;
}

void purple_http_request_header_set(PurpleHttpRequest *request,
	const gchar *key, const gchar *value)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(key != NULL);

	purple_http_headers_remove(request->headers, key);
	if (value)
		purple_http_headers_add(request->headers, key, value);
}

void purple_http_request_header_set_printf(PurpleHttpRequest *request,
	const gchar *key, const gchar *format, ...)
{
	va_list args;
	gchar *value;

	g_return_if_fail(request != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(format != NULL);

	va_start(args, format);
	value = g_strdup_vprintf(format, args);
	va_end(args);

	purple_http_request_header_set(request, key, value);
	g_free(value);
}

void purple_http_request_header_add(PurpleHttpRequest *request,
	const gchar *key, const gchar *value)
{
	g_return_if_fail(request != NULL);
	g_return_if_fail(key != NULL);

	purple_http_headers_add(request->headers, key, value);
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

gboolean purple_http_response_is_successful(PurpleHttpResponse *response)
{
	int code;

	g_return_val_if_fail(response != NULL, FALSE);

	code = response->code;

	if (code <= 0)
		return FALSE;

	/* TODO: HTTP/1.1 100 Continue */

	if (code / 100 == 2)
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

	if (response->error != NULL)
		return response->error;

	if (!purple_http_response_is_successful(response)) {
		static gchar errmsg[200];
		if (response->code <= 0) {
			g_snprintf(errmsg, sizeof(errmsg),
				_("Unknown HTTP error"));
		} else {
			g_snprintf(errmsg, sizeof(errmsg),
				_("Invalid HTTP response code (%d)"),
				response->code);
		}
		return errmsg;
	}

	return NULL;
}

gsize purple_http_response_get_data_len(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, 0);

	if (response->contents == NULL)
		return 0;

	return response->contents->len;
}

const gchar * purple_http_response_get_data(PurpleHttpResponse *response, size_t *len)
{
	const gchar *ret = "";

	g_return_val_if_fail(response != NULL, "");

	if (response->contents != NULL) {
		ret = response->contents->str;
		if(len)
			*len = response->contents->len;
	} else {
		if(len)
			*len = 0;
	}

	return ret;
}

const GList * purple_http_response_get_all_headers(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, NULL);

	return purple_http_headers_get_all(response->headers);
}

const GList * purple_http_response_get_headers_by_name(
	PurpleHttpResponse *response, const gchar *name)
{
	g_return_val_if_fail(response != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	return purple_http_headers_get_all_by_name(response->headers, name);
}

const gchar * purple_http_response_get_header(PurpleHttpResponse *response,
	const gchar *name)
{
	g_return_val_if_fail(response != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	return purple_http_headers_get(response->headers, name);
}

/*** URL functions ************************************************************/

PurpleHttpURL *
purple_http_url_parse(const char *raw_url)
{
	PurpleHttpURL *url;
	GMatchInfo *match_info;

	gchar *host_full, *tmp;

	g_return_val_if_fail(raw_url != NULL, NULL);

	url = g_new0(PurpleHttpURL, 1);

	if (!g_regex_match(purple_http_re_url, raw_url, 0, &match_info)) {
		if (purple_debug_is_verbose() && purple_debug_is_unsafe()) {
			purple_debug_warning("http",
				"Invalid URL provided: %s\n",
				raw_url);
		}
		return NULL;
	}

	url->protocol = g_match_info_fetch(match_info, 1);
	host_full = g_match_info_fetch(match_info, 2);
	url->path = g_match_info_fetch(match_info, 3);
	url->fragment = g_match_info_fetch(match_info, 4);
	g_match_info_free(match_info);

	if (url->protocol[0] == '\0') {
		g_free(url->protocol);
		url->protocol = NULL;
	} else if (url->protocol != NULL) {
		tmp = url->protocol;
		url->protocol = g_ascii_strdown(url->protocol, -1);
		g_free(tmp);
	}
	if (host_full[0] == '\0') {
		g_free(host_full);
		host_full = NULL;
	}
	if (url->path[0] == '\0') {
		g_free(url->path);
		url->path = NULL;
	}
	if ((url->protocol == NULL) != (host_full == NULL))
		purple_debug_warning("http", "Protocol or host not present "
			"(unlikely case)\n");

	if (host_full) {
		gchar *port_str;

		if (!g_regex_match(purple_http_re_url_host, host_full, 0,
			&match_info)) {
			if (purple_debug_is_verbose() &&
				purple_debug_is_unsafe()) {
				purple_debug_warning("http",
					"Invalid host provided for URL: %s\n",
					raw_url);
			}

			g_free(host_full);
			purple_http_url_free(url);
			return NULL;
		}

		url->username = g_match_info_fetch(match_info, 1);
		url->password = g_match_info_fetch(match_info, 2);
		url->host = g_match_info_fetch(match_info, 3);
		port_str = g_match_info_fetch(match_info, 4);

		if (port_str && port_str[0])
			url->port = atoi(port_str);

		if (url->username[0] == '\0') {
			g_free(url->username);
			url->username = NULL;
		}
		if (url->password[0] == '\0') {
			g_free(url->password);
			url->password = NULL;
		}
		if (url->host[0] == '\0') {
			g_free(url->host);
			url->host = NULL;
		} else if (url->host != NULL) {
			tmp = url->host;
			url->host = g_ascii_strdown(url->host, -1);
			g_free(tmp);
		}

		g_free(port_str);
		g_match_info_free(match_info);

		g_free(host_full);
		host_full = NULL;
	}

	if (url->host != NULL) {
		if (url->protocol == NULL)
			url->protocol = g_strdup("http");
		if (url->port == 0 && 0 == strcmp(url->protocol, "http"))
			url->port = 80;
		if (url->port == 0 && 0 == strcmp(url->protocol, "https"))
			url->port = 443;
		if (url->path == NULL)
			url->path = g_strdup("/");
		if (url->path[0] != '/')
			purple_debug_warning("http",
				"URL path doesn't start with slash\n");
	}

	return url;
}

void
purple_http_url_free(PurpleHttpURL *parsed_url)
{
	if (parsed_url == NULL)
		return;

	g_free(parsed_url->protocol);
	g_free(parsed_url->username);
	g_free(parsed_url->password);
	g_free(parsed_url->host);
	g_free(parsed_url->path);
	g_free(parsed_url->fragment);
	g_free(parsed_url);
}

void
purple_http_url_relative(PurpleHttpURL *base_url, PurpleHttpURL *relative_url)
{
	g_return_if_fail(base_url != NULL);
	g_return_if_fail(relative_url != NULL);

	if (relative_url->host) {
		g_free(base_url->protocol);
		base_url->protocol = g_strdup(relative_url->protocol);
		g_free(base_url->username);
		base_url->username = g_strdup(relative_url->username);
		g_free(base_url->password);
		base_url->password = g_strdup(relative_url->password);
		g_free(base_url->host);
		base_url->host = g_strdup(relative_url->host);
		base_url->port = relative_url->port;

		g_free(base_url->path);
		base_url->path = NULL;
	}

	if (relative_url->path) {
		if (relative_url->path[0] == '/' ||
			base_url->path == NULL) {
			g_free(base_url->path);
			base_url->path = g_strdup(relative_url->path);
		} else {
			gchar *last_slash = strrchr(base_url->path, '/');
			gchar *tmp;
			if (last_slash == NULL)
				base_url->path[0] = '\0';
			else
				last_slash[1] = '\0';
			tmp = base_url->path;
			base_url->path = g_strconcat(base_url->path,
				relative_url->path, NULL);
			g_free(tmp);
		}
	}

	g_free(base_url->fragment);
	base_url->fragment = g_strdup(relative_url->fragment);
}

gchar *
purple_http_url_print(PurpleHttpURL *parsed_url)
{
	GString *url = g_string_new("");
	gboolean before_host_printed = FALSE, host_printed = FALSE;
	gboolean port_is_default = FALSE;

	if (parsed_url->protocol) {
		g_string_append_printf(url, "%s://", parsed_url->protocol);
		before_host_printed = TRUE;
		if (parsed_url->port == 80 && 0 == strcmp(parsed_url->protocol,
			"http"))
			port_is_default = TRUE;
		if (parsed_url->port == 443 && 0 == strcmp(parsed_url->protocol,
			"https"))
			port_is_default = TRUE;
	}
	if (parsed_url->username || parsed_url->password) {
		if (parsed_url->username)
			g_string_append(url, parsed_url->username);
		g_string_append_printf(url, ":%s", parsed_url->password);
		g_string_append(url, "@");
		before_host_printed = TRUE;
	}
	if (parsed_url->host || parsed_url->port) {
		if (!parsed_url->host)
			g_string_append_printf(url, "{???}:%d",
				parsed_url->port);
		else {
			g_string_append(url, parsed_url->host);
			if (!port_is_default)
				g_string_append_printf(url, ":%d",
					parsed_url->port);
		}
		host_printed = TRUE;
	}
	if (parsed_url->path) {
		if (!host_printed && before_host_printed)
			g_string_append(url, "{???}");
		g_string_append(url, parsed_url->path);
	}
	if (parsed_url->fragment)
		g_string_append_printf(url, "#%s", parsed_url->fragment);

	return g_string_free(url, FALSE);
}

const gchar *
purple_http_url_get_protocol(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->protocol;
}

const gchar *
purple_http_url_get_username(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->username;
}

const gchar *
purple_http_url_get_password(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->password;
}

const gchar *
purple_http_url_get_host(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->host;
}

int
purple_http_url_get_port(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, 0);

	return parsed_url->port;
}

const gchar *
purple_http_url_get_path(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->path;
}

const gchar *
purple_http_url_get_fragment(const PurpleHttpURL *parsed_url)
{
	g_return_val_if_fail(parsed_url != NULL, NULL);

	return parsed_url->fragment;
}

/*** HTTP Subsystem ***********************************************************/

void purple_http_init(void)
{
	purple_http_re_url = g_regex_new("^"

		"(?:" /* host part beginning */
		"([a-z]+)\\:/*" /* protocol */
		"([^/]+)" /* username, password, host, port */
		")?" /* host part ending */

		"([^#]*)" /* path */

		"(?:#" "(.*)" ")?" /* fragment */

		"$", G_REGEX_OPTIMIZE | G_REGEX_CASELESS,
		G_REGEX_MATCH_NOTEMPTY, NULL);

	purple_http_re_url_host = g_regex_new("^"

		"(?:" /* user credentials part beginning */
		"([" PURPLE_HTTP_URL_CREDENTIALS_CHARS "]+)" /* username */
		"(?::([" PURPLE_HTTP_URL_CREDENTIALS_CHARS "]+))" /* password */
		"@)?" /* user credentials part ending */

		"([a-z0-9.-]+)" /* host */
		"(?::([0-9]+))?" /* port*/

		"$", G_REGEX_OPTIMIZE | G_REGEX_CASELESS,
		G_REGEX_MATCH_NOTEMPTY, NULL);

	purple_http_re_rfc1123 = g_regex_new(
		"^[a-z]+, " /* weekday */
		"([0-9]+) " /* date */
		"([a-z]+) " /* month */
		"([0-9]+) " /* year */
		"([0-9]+:[0-9]+:[0-9]+) " /* time */
		"(?:GMT|UTC)$",
		G_REGEX_OPTIMIZE | G_REGEX_CASELESS,
		G_REGEX_MATCH_NOTEMPTY, NULL);

	purple_http_hc_list = NULL;
	purple_http_hc_by_ptr = g_hash_table_new(g_direct_hash, g_direct_equal);
	purple_http_hc_by_gc = g_hash_table_new_full(g_direct_hash,
		g_direct_equal, NULL, (GDestroyNotify)g_list_free);
	purple_http_cancelling_gc = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void purple_http_foreach_conn_cancel(gpointer _hc, gpointer user_data)
{
	PurpleHttpConnection *hc = _hc;
	purple_http_conn_cancel(hc);
}

void purple_http_uninit(void)
{
	g_regex_unref(purple_http_re_url);
	purple_http_re_url = NULL;
	g_regex_unref(purple_http_re_url_host);
	purple_http_re_url_host = NULL;
	g_regex_unref(purple_http_re_rfc1123);
	purple_http_re_rfc1123 = NULL;

	g_list_foreach(purple_http_hc_list, purple_http_foreach_conn_cancel,
		NULL);

	if (purple_http_hc_list != NULL ||
		0 != g_hash_table_size(purple_http_hc_by_ptr) ||
		0 != g_hash_table_size(purple_http_hc_by_gc))
		purple_debug_warning("http",
			"Couldn't cleanup all connections.\n");

	g_list_free(purple_http_hc_list);
	purple_http_hc_list = NULL;
	g_hash_table_destroy(purple_http_hc_by_gc);
	purple_http_hc_by_gc = NULL;
	g_hash_table_destroy(purple_http_hc_by_ptr);
	purple_http_hc_by_ptr = NULL;
	g_hash_table_destroy(purple_http_cancelling_gc);
	purple_http_cancelling_gc = NULL;
}
