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
/**
 * SECTION:http
 * @section_id: libpurple-http
 * @short_description: <filename>http.h</filename>
 * @title: HTTP API
 */

#ifndef _PURPLE_HTTP_H_
#define _PURPLE_HTTP_H_

#include <glib.h>

#include "connection.h"

/**
 * PurpleHttpRequest:
 *
 * A structure containing all data required to generate a single HTTP request.
 */
typedef struct _PurpleHttpRequest PurpleHttpRequest;

/**
 * PurpleHttpConnection:
 *
 * A representation of actually running HTTP request. Can be used to cancel the
 * request.
 */
typedef struct _PurpleHttpConnection PurpleHttpConnection;

/**
 * PurpleHttpResponse:
 *
 * All information got with response for HTTP request.
 */
typedef struct _PurpleHttpResponse PurpleHttpResponse;

/**
 * PurpleHttpURL:
 *
 * Parsed representation for the URL.
 */
typedef struct _PurpleHttpURL PurpleHttpURL;

/**
 * PurpleHttpCookieJar:
 *
 * An collection of cookies, got from HTTP response or provided for HTTP
 * request.
 */
typedef struct _PurpleHttpCookieJar PurpleHttpCookieJar;

/**
 * PurpleHttpKeepalivePool:
 *
 * A pool of TCP connections for HTTP Keep-Alive session.
 */
typedef struct _PurpleHttpKeepalivePool PurpleHttpKeepalivePool;

/**
 * PurpleHttpConnectionSet:
 *
 * A set of running HTTP requests. Can be used to cancel all of them at once.
 */
typedef struct _PurpleHttpConnectionSet PurpleHttpConnectionSet;

/**
 * PurpleHttpCallback:
 *
 * An callback called after performing (successfully or not) HTTP request.
 */
typedef void (*PurpleHttpCallback)(PurpleHttpConnection *http_conn,
	PurpleHttpResponse *response, gpointer user_data);

/**
 * PurpleHttpContentReaderCb:
 *
 * An callback called after storing data requested by PurpleHttpContentReader.
 */
typedef void (*PurpleHttpContentReaderCb)(PurpleHttpConnection *http_conn,
	gboolean success, gboolean eof, size_t stored);

/**
 * PurpleHttpContentReader:
 * @http_conn: Connection, which requests data.
 * @buffer:    Buffer to store data to (with offset ignored).
 * @offset:    Position, from where to read data.
 * @length:    Length of data to read.
 * @user_data: The user data passed with callback function.
 * @cb:        The function to call after storing data to buffer.
 *
 * An callback for getting large request contents (ie. from file stored on
 * disk).
 */
typedef void (*PurpleHttpContentReader)(PurpleHttpConnection *http_conn,
	gchar *buffer, size_t offset, size_t length, gpointer user_data,
	PurpleHttpContentReaderCb cb);

/**
 * PurpleHttpContentWriter:
 * @http_conn: Connection, which requests data.
 * @response:  Response at point got so far (may change later).
 * @buffer:    Buffer to read data from (with offset ignored).
 * @offset:    Position of data got (its value is offset + length of
 *                  previous call), can be safely ignored.
 * @length:    Length of data read.
 * @user_data: The user data passed with callback function.
 *
 * An callback for writting large response contents.
 *
 * Returns:          TRUE, if succeeded, FALSE otherwise.
 */
typedef gboolean (*PurpleHttpContentWriter)(PurpleHttpConnection *http_conn,
	PurpleHttpResponse *response, const gchar *buffer, size_t offset,
	size_t length, gpointer user_data);

/**
 * PurpleHttpProgressWatcher:
 * @http_conn:     The HTTP Connection.
 * @reading_state: FALSE, is we are sending the request, TRUE, when reading
 *                      the response.
 * @processed:     The amount of data already processed.
 * @total:         Total amount of data (in current state).
 * @user_data:     The user data passed with callback function.
 *
 * An callback for watching HTTP connection progress.
 */
typedef void (*PurpleHttpProgressWatcher)(PurpleHttpConnection *http_conn,
	gboolean reading_state, int processed, int total, gpointer user_data);

G_BEGIN_DECLS

/**************************************************************************/
/** @name Performing HTTP requests                                        */
/**************************************************************************/
/*@{*/

/**
 * purple_http_get:
 * @gc:        The connection for which the request is needed, or NULL.
 * @callback:  The callback function.
 * @user_data: The user data to pass to the callback function.
 * @url:       The URL.
 *
 * Fetches the data from a URL with GET request, and passes it to a callback
 * function.
 *
 * Returns:          The HTTP connection struct.
 */
PurpleHttpConnection * purple_http_get(PurpleConnection *gc,
	PurpleHttpCallback callback, gpointer user_data, const gchar *url);

/**
 * purple_http_get_printf:
 * @gc:        The connection for which the request is needed, or NULL.
 * @callback:  The callback function.
 * @user_data: The user data to pass to the callback function.
 * @format:    The format string.
 *
 * Constructs an URL and fetches the data from it with GET request, then passes
 * it to a callback function.
 *
 * Returns:          The HTTP connection struct.
 */
PurpleHttpConnection * purple_http_get_printf(PurpleConnection *gc,
	PurpleHttpCallback callback, gpointer user_data,
	const gchar *format, ...) G_GNUC_PRINTF(4, 5);

/**
 * purple_http_request:
 * @gc:        The connection for which the request is needed, or NULL.
 * @request:   The request.
 * @callback:  The callback function.
 * @user_data: The user data to pass to the callback function.
 *
 * Fetches a HTTP request and passes the response to a callback function.
 * Provided request struct can be shared by multiple http requests but can not
 * be modified when any of these is running.
 *
 * Returns:          The HTTP connection struct.
 */
PurpleHttpConnection * purple_http_request(PurpleConnection *gc,
	PurpleHttpRequest *request, PurpleHttpCallback callback,
	gpointer user_data);

/**************************************************************************/
/** @name HTTP connection API                                             */
/**************************************************************************/
/*@{*/

/**
 * purple_http_conn_cancel:
 * @http_conn: The data returned when you initiated the HTTP request.
 *
 * Cancel a pending HTTP request.
 */
void purple_http_conn_cancel(PurpleHttpConnection *http_conn);

/**
 * purple_http_conn_cancel_all:
 * @gc: The handle.
 *
 * Cancels all HTTP connections associated with the specified handle.
 */
void purple_http_conn_cancel_all(PurpleConnection *gc);

/**
 * purple_http_conn_is_running:
 * @http_conn: The HTTP connection (may be invalid pointer).
 *
 * Checks, if provided HTTP request is running.
 *
 * Returns:          TRUE, if provided connection is currently running.
 */
gboolean purple_http_conn_is_running(PurpleHttpConnection *http_conn);

/**
 * purple_http_conn_get_request:
 * @http_conn: The HTTP connection.
 *
 * Gets PurpleHttpRequest used for specified HTTP connection.
 *
 * Returns:          The PurpleHttpRequest object.
 */
PurpleHttpRequest * purple_http_conn_get_request(
	PurpleHttpConnection *http_conn);

/**
 * purple_http_conn_get_cookie_jar:
 * @http_conn: The HTTP connection.
 *
 * Gets cookie jar used within connection.
 *
 * Returns:          The cookie jar.
 */
PurpleHttpCookieJar * purple_http_conn_get_cookie_jar(
	PurpleHttpConnection *http_conn);

/**
 * purple_http_conn_get_purple_connection:
 * @http_conn: The HTTP connection.
 *
 * Gets PurpleConnection tied with specified HTTP connection.
 *
 * Returns:          The PurpleConnection object.
 */
PurpleConnection * purple_http_conn_get_purple_connection(
	PurpleHttpConnection *http_conn);

/**
 * purple_http_conn_set_progress_watcher:
 * @http_conn:          The HTTP connection.
 * @watcher:            The watcher.
 * @user_data:          The user data to pass to the callback function.
 * @interval_threshold: Minimum interval (in microseconds) of calls to
 *                           watcher, or -1 for default.
 *
 * Sets the watcher, called after writing or reading data to/from HTTP stream.
 * May be used for updating transfer progress gauge.
 */
void purple_http_conn_set_progress_watcher(PurpleHttpConnection *http_conn,
	PurpleHttpProgressWatcher watcher, gpointer user_data,
	gint interval_threshold);

/*@}*/


/**************************************************************************/
/** @name URL processing API                                              */
/**************************************************************************/
/*@{*/

/**
 * purple_http_url_parse:
 * @url: The URL to parse.
 *
 * Parses a URL.
 *
 * The returned data must be freed with purple_http_url_free.
 *
 * Returns:    The parsed url or NULL, if the URL is invalid.
 */
PurpleHttpURL *
purple_http_url_parse(const char *url);

/**
 * purple_http_url_free:
 * @parsed_url: The parsed URL struct, or NULL.
 *
 * Frees the parsed URL struct.
 */
void
purple_http_url_free(PurpleHttpURL *parsed_url);

/**
 * purple_http_url_relative:
 * @base_url:     The base URL. The result is stored here.
 * @relative_url: The relative URL.
 *
 * Converts the base URL to the absolute form of the provided relative URL.
 *
 * Example: "https://example.com/path/to/file.html" + "subdir/other-file.html" =
 *          "https://example.com/path/to/subdir/another-file.html"
 */
void
purple_http_url_relative(PurpleHttpURL *base_url, PurpleHttpURL *relative_url);

/**
 * purple_http_url_print:
 * @parsed_url: The URL struct.
 *
 * Converts the URL struct to the printable form. The result may not be a valid
 * URL (in cases, when the struct doesn't have all fields filled properly).
 *
 * The result must be g_free'd.
 *
 * Returns:           The printable form of the URL.
 */
gchar *
purple_http_url_print(PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_protocol:
 * @parsed_url: The URL struct.
 *
 * Gets the protocol part of URL.
 *
 * Returns:           The protocol.
 */
const gchar *
purple_http_url_get_protocol(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_username:
 * @parsed_url: The URL struct.
 *
 * Gets the username part of URL.
 *
 * Returns:           The username.
 */
const gchar *
purple_http_url_get_username(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_password:
 * @parsed_url: The URL struct.
 *
 * Gets the password part of URL.
 *
 * Returns:           The password.
 */
const gchar *
purple_http_url_get_password(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_host:
 * @parsed_url: The URL struct.
 *
 * Gets the hostname part of URL.
 *
 * Returns:           The hostname.
 */
const gchar *
purple_http_url_get_host(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_port:
 * @parsed_url: The URL struct.
 *
 * Gets the port part of URL.
 *
 * Returns:           The port number.
 */
int
purple_http_url_get_port(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_path:
 * @parsed_url: The URL struct.
 *
 * Gets the path part of URL.
 *
 * Returns:           The path.
 */
const gchar *
purple_http_url_get_path(const PurpleHttpURL *parsed_url);

/**
 * purple_http_url_get_fragment:
 * @parsed_url: The URL struct.
 *
 * Gets the fragment part of URL.
 *
 * Returns:           The fragment.
 */
const gchar *
purple_http_url_get_fragment(const PurpleHttpURL *parsed_url);

/*@}*/


/**************************************************************************/
/** @name Cookie jar API                                                  */
/**************************************************************************/
/*@{*/

/**
 * purple_http_cookie_jar_new:
 *
 * Creates new cookie jar,
 *
 * Returns: empty cookie jar.
 */
PurpleHttpCookieJar * purple_http_cookie_jar_new(void);

/**
 * purple_http_cookie_jar_ref:
 * @cookie_jar: The cookie jar.
 *
 * Increment the reference count.
 */
void purple_http_cookie_jar_ref(PurpleHttpCookieJar *cookie_jar);

/**
 * purple_http_cookie_jar_unref:
 * @cookie_jar: The cookie jar.
 *
 * Decrement the reference count.
 *
 * If the reference count reaches zero, the cookie jar will be freed.
 *
 * Returns: @cookie_jar or %NULL if the reference count reached zero.
 */
PurpleHttpCookieJar * purple_http_cookie_jar_unref(
	PurpleHttpCookieJar *cookie_jar);

/**
 * purple_http_cookie_jar_set:
 * @cookie_jar: The cookie jar.
 * @name:       Cookie name.
 * @value:      Cookie contents.
 *
 * Sets the cookie.
 */
void purple_http_cookie_jar_set(PurpleHttpCookieJar *cookie_jar,
	const gchar *name, const gchar *value);

/**
 * purple_http_cookie_jar_get:
 * @cookie_jar: The cookie jar.
 * @name:       Cookie name.
 *
 * Gets the cookie.
 *
 * Returns:           Cookie contents, or NULL, if cookie doesn't exists.
 */
const gchar * purple_http_cookie_jar_get(PurpleHttpCookieJar *cookie_jar,
	const gchar *name);

/**
 * purple_http_cookie_jar_is_empty:
 * @cookie_jar: The cookie jar.
 *
 * Checks, if the cookie jar contains any cookies.
 *
 * Returns:           TRUE, if cookie jar contains any cookie, FALSE otherwise.
 */
gboolean purple_http_cookie_jar_is_empty(PurpleHttpCookieJar *cookie_jar);

/*@}*/


/**************************************************************************/
/** @name HTTP Request API                                                */
/**************************************************************************/
/*@{*/

/**
 * purple_http_request_new:
 * @url: The URL to request for, or NULL to leave empty (to be set with
 *            purple_http_request_set_url).
 *
 * Creates the new instance of HTTP request configuration.
 *
 * Returns: The new instance of HTTP request struct.
 */
PurpleHttpRequest * purple_http_request_new(const gchar *url);

/**
 * purple_http_request_ref:
 * @request: The request.
 *
 * Increment the reference count.
 */
void purple_http_request_ref(PurpleHttpRequest *request);

/**
 * purple_http_request_unref:
 * @request: The request.
 *
 * Decrement the reference count.
 *
 * If the reference count reaches zero, the http request struct will be freed.
 *
 * Returns: @request or %NULL if the reference count reached zero.
 */
PurpleHttpRequest * purple_http_request_unref(PurpleHttpRequest *request);

/**
 * purple_http_request_set_url:
 * @request: The request.
 * @url:     The url.
 *
 * Sets URL for HTTP request.
 */
void purple_http_request_set_url(PurpleHttpRequest *request, const gchar *url);

/**
 * purple_http_request_set_url_printf:
 * @request: The request.
 * @format:  The format string.
 *
 * Constructs and sets an URL for HTTP request.
 */
void purple_http_request_set_url_printf(PurpleHttpRequest *request,
	const gchar *format, ...) G_GNUC_PRINTF(2, 3);

/**
 * purple_http_request_get_url:
 * @request: The request.
 *
 * Gets URL set for the HTTP request.
 *
 * Returns:        URL set for this request.
 */
const gchar * purple_http_request_get_url(PurpleHttpRequest *request);

/**
 * purple_http_request_set_method:
 * @request: The request.
 * @method:  The method, or NULL for default.
 *
 * Sets custom HTTP method used for the request.
 */
void purple_http_request_set_method(PurpleHttpRequest *request,
	const gchar *method);

/**
 * purple_http_request_get_method:
 * @request: The request.
 *
 * Gets HTTP method set for the request.
 *
 * Returns:        The method.
 */
const gchar * purple_http_request_get_method(PurpleHttpRequest *request);

/**
 * purple_http_request_set_keepalive_pool:
 * @request: The request.
 * @pool:    The new KeepAlive pool, or NULL to reset.
 *
 * Sets HTTP KeepAlive connections pool for the request.
 *
 * It increases pool's reference count.
 */
void
purple_http_request_set_keepalive_pool(PurpleHttpRequest *request,
	PurpleHttpKeepalivePool *pool);

/**
 * purple_http_request_get_keepalive_pool:
 * @request: The request.
 *
 * Gets HTTP KeepAlive connections pool associated with the request.
 *
 * It doesn't affect pool's reference count.
 *
 * Returns:        The KeepAlive pool, used for the request.
 */
PurpleHttpKeepalivePool *
purple_http_request_get_keepalive_pool(PurpleHttpRequest *request);

/**
 * purple_http_request_set_contents:
 * @request:  The request.
 * @contents: The contents.
 * @length:   The length of contents (-1 if it's a NULL-terminated string)
 *
 * Sets contents of HTTP request (for example, POST data).
 */
void purple_http_request_set_contents(PurpleHttpRequest *request,
	const gchar *contents, int length);

/**
 * purple_http_request_set_contents_reader:
 * @request:         The request.
 * @reader:          The reader callback.
 * @contents_length: The size of all contents.
 * @user_data:       The user data to pass to the callback function.
 *
 * Sets contents reader for HTTP request, used mainly for possible large
 * uploads.
 */
void purple_http_request_set_contents_reader(PurpleHttpRequest *request,
	PurpleHttpContentReader reader, int contents_length, gpointer user_data);

/**
 * purple_http_request_set_response_writer:
 * @request:   The request.
 * @writer:    The writer callback, or %NULL to remove existing.
 * @user_data: The user data to pass to the callback function.
 *
 * Set contents writer for HTTP response.
 */
void purple_http_request_set_response_writer(PurpleHttpRequest *request,
	PurpleHttpContentWriter writer, gpointer user_data);

/**
 * purple_http_request_set_timeout:
 * @request: The request.
 * @timeout: Time (in seconds) after that timeout will be cancelled,
 *                -1 for infinite time.
 *
 * Set maximum amount of time, that request is allowed to run.
 */
void purple_http_request_set_timeout(PurpleHttpRequest *request, int timeout);

/**
 * purple_http_request_get_timeout:
 * @request: The request.
 *
 * Get maximum amount of time, that request is allowed to run.
 *
 * Returns:        Timeout currently set (-1 for infinite).
 */
int purple_http_request_get_timeout(PurpleHttpRequest *request);

/**
 * purple_http_request_set_max_redirects:
 * @request:       The request.
 * @max_redirects: Maximum amount of redirects, or -1 for unlimited.
 *
 * Sets maximum amount of redirects.
 */
void purple_http_request_set_max_redirects(PurpleHttpRequest *request,
	int max_redirects);

/**
 * purple_http_request_get_max_redirects:
 * @request: The request.
 *
 * Gets maximum amount of redirects.
 *
 * Returns:        Current maximum amount of redirects (-1 for unlimited).
 */
int purple_http_request_get_max_redirects(PurpleHttpRequest *request);

/**
 * purple_http_request_set_cookie_jar:
 * @request:    The request.
 * @cookie_jar: The cookie jar.
 *
 * Sets cookie jar used for the request.
 */
void purple_http_request_set_cookie_jar(PurpleHttpRequest *request,
	PurpleHttpCookieJar *cookie_jar);

/**
 * purple_http_request_get_cookie_jar:
 * @request: The request.
 *
 * Gets cookie jar used for the request.
 *
 * Returns:        The cookie jar.
 */
PurpleHttpCookieJar * purple_http_request_get_cookie_jar(
	PurpleHttpRequest *request);

/**
 * purple_http_request_set_http11:
 * @request: The request.
 * @http11:  TRUE for HTTP/1.1, FALSE for HTTP/1.0.
 *
 * Sets HTTP version to use.
 */
void purple_http_request_set_http11(PurpleHttpRequest *request,
	gboolean http11);

/**
 * purple_http_request_is_http11:
 * @request: The request.
 *
 * Gets used HTTP version.
 *
 * Returns:        TRUE, if we use HTTP/1.1, FALSE for HTTP/1.0.
 */
gboolean purple_http_request_is_http11(PurpleHttpRequest *request);

/**
 * purple_http_request_set_max_len:
 * @request: The request.
 * @max_len: Maximum length of response to read (-1 for the maximum
 *                supported amount).
 *
 * Sets maximum length of response content to read.
 *
 * Headers length doesn't count here.
 *
 */
void purple_http_request_set_max_len(PurpleHttpRequest *request, int max_len);

/**
 * purple_http_request_get_max_len:
 * @request: The request.
 *
 * Gets maximum length of response content to read.
 *
 * Returns:        Maximum length of response to read, or -1 if unlimited.
 */
int purple_http_request_get_max_len(PurpleHttpRequest *request);

/**
 * purple_http_request_header_set:
 * @request: The request.
 * @key:     A header to be set.
 * @value:   A value to set, or NULL to remove specified header.
 *
 * Sets (replaces, if exists) specified HTTP request header with provided value.
 *
 * See purple_http_request_header_add().
 */
void purple_http_request_header_set(PurpleHttpRequest *request,
	const gchar *key, const gchar *value);

/**
 * purple_http_request_header_set_printf:
 * @request: The request.
 * @key:     A header to be set.
 * @format:  The format string.
 *
 * Constructs and sets (replaces, if exists) specified HTTP request header.
 */
void purple_http_request_header_set_printf(PurpleHttpRequest *request,
	const gchar *key, const gchar *format, ...) G_GNUC_PRINTF(3, 4);

/**
 * purple_http_request_header_add:
 * @key:   A header to be set.
 * @value: A value to set.
 *
 * Adds (without replacing, if exists) an HTTP request header.
 *
 * See purple_http_request_header_set().
 */
void purple_http_request_header_add(PurpleHttpRequest *request,
	const gchar *key, const gchar *value);

/*@}*/


/**************************************************************************/
/** @name HTTP Keep-Alive pool API                                        */
/**************************************************************************/
/*@{*/

/**
 * purple_http_keepalive_pool_new:
 *
 * Creates a new HTTP Keep-Alive pool.
 */
PurpleHttpKeepalivePool *
purple_http_keepalive_pool_new(void);

/**
 * purple_http_keepalive_pool_ref:
 * @pool: The HTTP Keep-Alive pool.
 *
 * Increment the reference count.
 */
void
purple_http_keepalive_pool_ref(PurpleHttpKeepalivePool *pool);

/**
 * purple_http_keepalive_pool_unref:
 * @pool: The HTTP Keep-Alive pool.
 *
 * Decrement the reference count.
 *
 * If the reference count reaches zero, the pool will be freed and all
 * connections will be closed.
 *
 * Returns: @pool or %NULL if the reference count reached zero.
 */
PurpleHttpKeepalivePool *
purple_http_keepalive_pool_unref(PurpleHttpKeepalivePool *pool);

/**
 * purple_http_keepalive_pool_set_limit_per_host:
 * @pool:  The HTTP Keep-Alive pool.
 * @limit: The new limit, 0 for unlimited.
 *
 * Sets maximum allowed number of connections to specific host-triple (is_ssl +
 * hostname + port).
 */
void
purple_http_keepalive_pool_set_limit_per_host(PurpleHttpKeepalivePool *pool,
	guint limit);

/**
 * purple_http_keepalive_pool_get_limit_per_host:
 * @pool: The HTTP Keep-Alive pool.
 *
 * Gets maximum allowed number of connections to specific host-triple (is_ssl +
 * hostname + port).
 *
 * Returns:     The limit.
 */
guint
purple_http_keepalive_pool_get_limit_per_host(PurpleHttpKeepalivePool *pool);

/*@}*/


/**************************************************************************/
/** @name HTTP connection set API                                         */
/**************************************************************************/
/*@{*/

PurpleHttpConnectionSet *
purple_http_connection_set_new(void);

void
purple_http_connection_set_destroy(PurpleHttpConnectionSet *set);

void
purple_http_connection_set_add(PurpleHttpConnectionSet *set,
	PurpleHttpConnection *http_conn);

/*@}*/


/**************************************************************************/
/** @name HTTP response API                                               */
/**************************************************************************/
/*@{*/

/**
 * purple_http_response_is_successful:
 * @response: The response.
 *
 * Checks, if HTTP request was performed successfully.
 *
 * Returns:         TRUE, if request was performed successfully.
 */
gboolean purple_http_response_is_successful(PurpleHttpResponse *response);

/**
 * purple_http_response_get_code:
 * @response: The response.
 *
 * Gets HTTP response code.
 *
 * Returns:         HTTP response code.
 */
int purple_http_response_get_code(PurpleHttpResponse *response);

/**
 * purple_http_response_get_error:
 * @response: The response.
 *
 * Gets error description.
 *
 * Returns:         Localized error description or NULL, if there was no error.
 */
const gchar * purple_http_response_get_error(PurpleHttpResponse *response);

/**
 * purple_http_response_get_data_len:
 * @response: The response.
 *
 * Gets HTTP response data length.
 *
 * Returns:         Data length;
 */
gsize purple_http_response_get_data_len(PurpleHttpResponse *response);

/**
 * purple_http_response_get_data:
 * @response: The response.
 * @len:      Return address for the size of the data.  Can be NULL.
 *
 * Gets HTTP response data.
 *
 * Response data is not written, if writer callback was set for request.
 *
 * Returns:         The data.
 */
const gchar * purple_http_response_get_data(PurpleHttpResponse *response, size_t *len);

/**
 * purple_http_response_get_all_headers:
 * @response: The response.
 *
 * Gets all headers got with response.
 *
 * Returns:         GList of PurpleKeyValuePair, which keys are header field
 *                 names (gchar*) and values are its contents (gchar*).
 */
const GList * purple_http_response_get_all_headers(PurpleHttpResponse *response);

/**
 * purple_http_response_get_headers_by_name:
 * @response: The response.
 * @name:     The name of header field.
 *
 * Gets all headers with specified name got with response.
 *
 * Returns:         GList of header field records contents (gchar*).
 */
const GList * purple_http_response_get_headers_by_name(
	PurpleHttpResponse *response, const gchar *name);

/**
 * purple_http_response_get_header:
 * @response: The response.
 * @name:     The name of header field.
 *
 * Gets one header contents with specified name got with response.
 *
 * To get all headers with the same name, use
 * purple_http_response_get_headers_by_name instead.
 *
 * Returns:         Header field contents or NULL, if there is no such one.
 */
const gchar * purple_http_response_get_header(PurpleHttpResponse *response,
	const gchar *name);

/*@}*/


/**************************************************************************/
/** @name HTTP Subsystem                                                  */
/**************************************************************************/
/*@{*/

/**
 * purple_http_init:
 *
 * Initializes the http subsystem.
 */
void purple_http_init(void);

/**
 * purple_http_uninit:
 *
 * Uninitializes the http subsystem.
 */
void purple_http_uninit(void);

/*@}*/

G_END_DECLS

#endif /* _PURPLE_HTTP_H_ */
