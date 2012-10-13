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
};

struct _PurpleHttpResponse
{
	int code;

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

static gboolean purple_http_request_dummy_timeout(gpointer user_data)
{
	PurpleHttpConnection *hc = user_data;
	PurpleHttpResponse *response = hc->response;

	response->code = 200;
	response->data = g_strdup(purple_http_url_debug(hc->url));
	response->data_len = strlen(response->data);

	purple_http_connection_terminate(hc);

	return FALSE;
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
	if (!hc->url) {
		purple_debug_error("http", "Invalid URL requested.\n");
		purple_http_connection_terminate(hc);
		return NULL;
	}

	purple_timeout_add_seconds(1, purple_http_request_dummy_timeout, hc);

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
