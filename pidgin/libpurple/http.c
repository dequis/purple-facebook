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

struct _PurpleHttpSocket
{
	gboolean is_connected;
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
};

struct _PurpleHttpResponse
{
	int code;
	gchar *error;

	gchar *data;
	gsize data_len;
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

static PurpleHttpConnection * purple_http_connection_new(
	PurpleHttpRequest *request);
static void purple_http_connection_terminate(PurpleHttpConnection *hc);

static PurpleHttpResponse * purple_http_response_new(void);
static void purple_http_response_free(PurpleHttpResponse *response);

static PurpleHttpURL * purple_http_url_parse(const char *url);
static void purple_http_url_free(PurpleHttpURL *parsed_url);

static const gchar * purple_http_url_debug(PurpleHttpURL *parsed_url);

/*** HTTP protocol backend ****************************************************/

static void purple_http_dummy_success(PurpleHttpConnection *hc)
{
	PurpleHttpResponse *response = hc->response;

	response->code = 200;
	response->data = g_strdup(purple_http_url_debug(hc->url));
	response->data_len = strlen(response->data);

	purple_http_conn_cancel(hc);
}

static void _purple_http_disconnect(PurpleHttpConnection *hc);

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

static void _purple_http_send(gpointer _hc, gint fd, PurpleInputCondition cond)
{ // url_fetch_send_cb
	PurpleHttpConnection *hc = _hc;

	purple_debug_misc("http", "[tmp] sending...\n");

	purple_http_dummy_success(hc);
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
	_purple_http_send(hc, fd, PURPLE_INPUT_WRITE);
}

static void _purple_http_connected_ssl(gpointer _hc,
	PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	PurpleHttpConnection *hc = _hc;
	PurpleHttpSocket *hs = &hc->socket;

	hs->fd = hs->ssl_connection->fd;
	hs->inpa = purple_input_add(hs->fd, PURPLE_INPUT_WRITE,
		_purple_http_send, hc);
	_purple_http_send(hc, hs->fd, PURPLE_INPUT_WRITE);
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

	if (!hs->is_connected)
		return;

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
	hc->socket.is_connected = TRUE;

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

	if (hc->socket.is_connected)
		purple_debug_error("http", "Socket is still connected!");

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
	g_free(response->error);
	g_free(response);
}

gboolean purple_http_response_is_successfull(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, FALSE);

	return response->code == 200; /* just temporary */
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

	return response->data_len;
}

const gchar * purple_http_response_get_data(PurpleHttpResponse *response)
{
	g_return_val_if_fail(response != NULL, NULL);

	return response->data;
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
