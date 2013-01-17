/**
 * @file http.h HTTP API
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

#ifndef _PURPLE_HTTP_H_
#define _PURPLE_HTTP_H_

#include <glib.h>

#include "connection.h"

/**
 * A structure containing all data required to generate a single HTTP request.
 */
typedef struct _PurpleHttpRequest PurpleHttpRequest;

/**
 * A representation of actually running HTTP request. Can be used to cancel the
 * request.
 */
typedef struct _PurpleHttpConnection PurpleHttpConnection;

/**
 * All information got with response for HTTP request.
 */
typedef struct _PurpleHttpResponse PurpleHttpResponse;

/**
 * An collection of cookies, got from HTTP response or provided for HTTP
 * request.
 */
typedef struct _PurpleHttpCookieJar PurpleHttpCookieJar;

/**
 * An callback called after performing (successfully or not) HTTP request.
 */
typedef void (*PurpleHttpCallback)(PurpleHttpConnection *http_conn,
	PurpleHttpResponse *response, gpointer user_data);

/**
 * An callback called after storing data requested by PurpleHttpContentReader.
 */
typedef void (*PurpleHttpContentReaderCb)(PurpleHttpConnection *http_conn,
	gboolean success, gboolean eof, size_t stored);

/**
 * An callback for getting large request contents (ie. from file stored on
 * disk).
 *
 * @param http_conn Connection, which requests data.
 * @param buffer    Buffer to store data to (with offset ignored).
 * @param offset    Position, from where to read data.
 * @param length    Length of data to read.
 * @param user_data The user data passed with callback function.
 * @param cb        The function to call after storing data to buffer.
 */
typedef void (*PurpleHttpContentReader)(PurpleHttpConnection *http_conn,
	gchar *buffer, size_t offset, size_t length, gpointer user_data,
	PurpleHttpContentReaderCb cb);

/**
 * An callback for writting large response contents.
 *
 * @param http_conn Connection, which requests data.
 * @param response  Response at point got so far (may change later).
 * @param buffer    Buffer to read data from (with offset ignored).
 * @param offset    Position of data got (its value is offset + length of
 *                  previous call), can be safely ignored.
 * @param length    Length of data read.
 * @param user_data The user data passed with callback function.
 * @return          TRUE, if succeeded, FALSE otherwise.
 */
typedef gboolean (*PurpleHttpContentWriter)(PurpleHttpConnection *http_conn,
	PurpleHttpResponse *response, const gchar *buffer, size_t offset,
	size_t length, gpointer user_data);

/**
 * An callback for watching HTTP connection progress.
 *
 * @param http_conn     The HTTP Connection.
 * @param reading_state FALSE, is we are sending the request, TRUE, when reading
 *                      the response.
 * @param processed     The amount of data already processed.
 * @param total         Total amount of data (in current state).
 * @param user_data     The user data passed with callback function.
 */
typedef void (*PurpleHttpProgressWatcher)(PurpleHttpConnection *http_conn,
	gboolean reading_state, int processed, int total, gpointer user_data);

G_BEGIN_DECLS

/**************************************************************************/
/** @name Performing HTTP requests                                        */
/**************************************************************************/
/*@{*/

/**
 * Fetches the data from a URL with GET request, and passes it to a callback
 * function.
 *
 * @param gc       The connection for which the request is needed, or NULL.
 * @param url      The URL.
 * @param callback The callback function.
 * @param data     The user data to pass to the callback function.
 * @return         The HTTP connection struct.
 */
PurpleHttpConnection * purple_http_get(PurpleConnection *gc, const gchar *url,
	PurpleHttpCallback callback, gpointer user_data);

/**
 * Fetches a HTTP request and passes the response to a callback function.
 * Provided request struct can be shared by multiple http requests but can not
 * be modified when any of these is running.
 *
 * @param gc        The connection for which the request is needed, or NULL.
 * @param request   The request.
 * @param callback  The callback function.
 * @param user_data The user data to pass to the callback function.
 * @return          The HTTP connection struct.
 */
PurpleHttpConnection * purple_http_request(PurpleConnection *gc,
	PurpleHttpRequest *request, PurpleHttpCallback callback,
	gpointer user_data);

/**************************************************************************/
/** @name HTTP connection API                                             */
/**************************************************************************/
/*@{*/

/**
 * Cancel a pending HTTP request.
 *
 * @param http_conn The data returned when you initiated the HTTP request.
 */
void purple_http_conn_cancel(PurpleHttpConnection *http_conn);

/**
 * Cancels all HTTP connections associated with the specified handle.
 *
 * @param gc The handle.
 */
void purple_http_conn_cancel_all(PurpleConnection *gc);

/**
 * Checks, if provided HTTP request is running.
 *
 * @param http_conn The HTTP connection (may be invalid pointer).
 * @return          TRUE, if provided connection is currently running.
 */
gboolean purple_http_conn_is_running(PurpleHttpConnection *http_conn);

/**
 * Gets PurpleHttpRequest used for specified HTTP connection.
 *
 * @param http_conn The HTTP connection.
 * @return          The PurpleHttpRequest object.
 */
PurpleHttpRequest * purple_http_conn_get_request(
	PurpleHttpConnection *http_conn);

/**
 * Gets cookie jar used within connection.
 *
 * @param http_conn The HTTP connection.
 * @return          The cookie jar.
 */
PurpleHttpCookieJar * purple_http_conn_get_cookie_jar(
	PurpleHttpConnection *http_conn);

/**
 * Gets PurpleConnection tied with specified HTTP connection.
 *
 * @param http_conn The HTTP connection.
 * @return          The PurpleConnection object.
 */
PurpleConnection * purple_http_conn_get_purple_connection(
	PurpleHttpConnection *http_conn);

/**
 * Sets the watcher, called after writing or reading data to/from HTTP stream.
 * May be used for updating transfer progress gauge.
 *
 * @param http_conn          The HTTP connection.
 * @param watcher            The watcher.
 * @param user_data          The user data to pass to the callback function.
 * @param interval_threshold Minimum interval (in microseconds) of calls to
 *                           watcher.
 */
void purple_http_conn_set_progress_watcher(PurpleHttpConnection *http_conn,
	PurpleHttpProgressWatcher watcher, gpointer user_data,
	guint interval_threshold);

/*@}*/


/**************************************************************************/
/** @name Cookie jar API                                                  */
/**************************************************************************/
/*@{*/

/**
 * Creates new cookie jar,
 *
 * @return empty cookie jar.
 */
PurpleHttpCookieJar * purple_http_cookie_jar_new(void);

/**
 * Increment the reference count.
 *
 * @param cookie_jar The cookie jar.
 */
void purple_http_cookie_jar_ref(PurpleHttpCookieJar *cookie_jar);

/**
 * Decrement the reference count.
 *
 * If the reference count reaches zero, the cookie jar will be freed.
 *
 * @param cookie_jar The cookie jar.
 * @return @a cookie_jar or @c NULL if the reference count reached zero.
 */
PurpleHttpCookieJar * purple_http_cookie_jar_unref(
	PurpleHttpCookieJar *cookie_jar);

/**
 * Sets the cookie.
 *
 * @param cookie_jar The cookie jar.
 * @param name       Cookie name.
 * @param value      Cookie contents.
 */
void purple_http_cookie_jar_set(PurpleHttpCookieJar *cookie_jar,
	const gchar *name, const gchar *value);

/**
 * Gets the cookie.
 *
 * @param cookie_jar The cookie jar.
 * @param name       Cookie name.
 * @return           Cookie contents, or NULL, if cookie doesn't exists.
 */
const gchar * purple_http_cookie_jar_get(PurpleHttpCookieJar *cookie_jar,
	const gchar *name);

/**
 * Checks, if the cookie jar contains any cookies.
 *
 * @param cookie_jar The cookie jar.
 * @return           TRUE, if cookie jar contains any cookie, FALSE otherwise.
 */
gboolean purple_http_cookie_jar_is_empty(PurpleHttpCookieJar *cookie_jar);

/*@}*/


/**************************************************************************/
/** @name HTTP Request API                                                */
/**************************************************************************/
/*@{*/

/**
 * Creates the new instance of HTTP request configuration.
 *
 * @param url The URL to request for.
 * @return The new instance of HTTP request struct.
 */
PurpleHttpRequest * purple_http_request_new(const gchar *url);

/**
 * Increment the reference count.
 *
 * @param request The request.
 */
void purple_http_request_ref(PurpleHttpRequest *request);

/**
 * Decrement the reference count.
 *
 * If the reference count reaches zero, the http request struct will be freed.
 *
 * @param request The request.
 * @return @a request or @c NULL if the reference count reached zero.
 */
PurpleHttpRequest * purple_http_request_unref(PurpleHttpRequest *request);

/**
 * Sets URL for HTTP request.
 *
 * @param request The request.
 * @param url     The url.
 */
void purple_http_request_set_url(PurpleHttpRequest *request, const gchar *url);

/**
 * Gets URL set for the HTTP request.
 *
 * @param request The request.
 * @return        URL set for this request.
 */
const gchar * purple_http_request_get_url(PurpleHttpRequest *request);

/**
 * Sets custom HTTP method used for the request.
 *
 * @param request The request.
 * @param method  The method, or NULL for default.
 */
void purple_http_request_set_method(PurpleHttpRequest *request,
	const gchar *method);

/**
 * Gets HTTP method set for the request.
 *
 * @param request The request.
 * @return        The method.
 */
const gchar * purple_http_request_get_method(PurpleHttpRequest *request);

/**
 * Sets contents of HTTP request (for example, POST data).
 *
 * @param request  The request.
 * @param contents The contents.
 * @param length   The length of contents (-1 if it's a NULL-terminated string)
 */
void purple_http_request_set_contents(PurpleHttpRequest *request,
	const gchar *contents, int length);

/**
 * Sets contents reader for HTTP request, used mainly for possible large
 * uploads.
 *
 * @param request       The request.
 * @param reader        The reader callback.
 * @param contents_size The size of all contents.
 * @param user_data     The user data to pass to the callback function.
 */
void purple_http_request_set_contents_reader(PurpleHttpRequest *request,
	PurpleHttpContentReader reader, int contents_length, gpointer user_data);

/**
 * Set contents writer for HTTP response.
 *
 * @param request   The request.
 * @param reader    The writer callback, or NULL to remove existing.
 * @param user_data The user data to pass to the callback function.
 */
void purple_http_request_set_response_writer(PurpleHttpRequest *request,
	PurpleHttpContentWriter writer, gpointer user_data);

/**
 * Set maximum amount of time, that request is allowed to run.
 *
 * @param request The request.
 * @param timeout Time (in seconds) after that timeout will be cancelled,
 *                -1 for infinite time.
 */
void purple_http_request_set_timeout(PurpleHttpRequest *request, int timeout);

/**
 * Get maximum amount of time, that request is allowed to run.
 *
 * @param request The request.
 * @return        Timeout currently set (-1 for infinite).
 */
int purple_http_request_get_timeout(PurpleHttpRequest *request);

/**
 * Sets maximum amount of redirects.
 *
 * @param request       The request.
 * @param max_redirects Maximum amount of redirects, or -1 for unlimited.
 */
void purple_http_request_set_max_redirects(PurpleHttpRequest *request,
	int max_redirects);

/**
 * Gets maximum amount of redirects.
 *
 * @param request The request.
 * @return        Current maximum amount of redirects (-1 for unlimited).
 */
int purple_http_request_get_max_redirects(PurpleHttpRequest *request);

/**
 * Sets cookie jar used for the request.
 *
 * @param request    The request.
 * @param cookie_jar The cookie jar.
 */
void purple_http_request_set_cookie_jar(PurpleHttpRequest *request,
	PurpleHttpCookieJar *cookie_jar);

/**
 * Gets cookie jar used for the request.
 *
 * @param request The request.
 * @return        The cookie jar.
 */
PurpleHttpCookieJar * purple_http_request_get_cookie_jar(
	PurpleHttpRequest *request);

/**
 * Sets HTTP version to use.
 *
 * @param request The request.
 * @param http11  TRUE for HTTP/1.1, FALSE for HTTP/1.0.
 */
void purple_http_request_set_http11(PurpleHttpRequest *request,
	gboolean http11);

/**
 * Gets used HTTP version.
 *
 * @param request The request.
 * @return        TRUE, if we use HTTP/1.1, FALSE for HTTP/1.0.
 */
gboolean purple_http_request_is_http11(PurpleHttpRequest *request);

/**
 * Sets maximum length of response content to read.
 *
 * Headers length doesn't count here.
 *
 * @param request The request.
 * @param max_len Maximum length of response to read (-1 for unlimited).
 */
void purple_http_request_set_max_len(PurpleHttpRequest *request, int max_len);

/**
 * Gets maximum length of response content to read.
 *
 * @param request The request.
 * @return        Maximum length of response to read, or -1 if unlimited.
 */
int purple_http_request_get_max_len(PurpleHttpRequest *request);

/**
 * Sets (replaces, if exists) specified HTTP request header with provided value.
 *
 * @param key   A header to be set.
 * @param value A value to set, or NULL to remove specified header from request.
 *
 * @see purple_http_request_header_add
 */
void purple_http_request_header_set(PurpleHttpRequest *request,
	const gchar *key, const gchar *value);

void purple_http_request_header_set_printf(PurpleHttpRequest *request,
	const gchar *key, const gchar *format, ...) G_GNUC_PRINTF(3, 4);

/**
 * Adds (without replacing, if exists) an HTTP request header.
 *
 * @param key   A header to be set.
 * @param value A value to set.
 *
 * @see purple_http_request_header_set
 */
void purple_http_request_header_add(PurpleHttpRequest *request,
	const gchar *key, const gchar *value);

/*@}*/

/**************************************************************************/
/** @name HTTP response API                                               */
/**************************************************************************/
/*@{*/

/**
 * Checks, if HTTP request was performed successfully.
 *
 * @param response The response.
 * @return         TRUE, if request was performed successfully.
 */
gboolean purple_http_response_is_successfull(PurpleHttpResponse *response);

/**
 * Gets HTTP response code.
 *
 * @param response The response.
 * @return         HTTP response code.
 */
int purple_http_response_get_code(PurpleHttpResponse *response);

/**
 * Gets error description.
 *
 * @param response The response.
 * @return         Localized error description or NULL, if there was no error.
 */
const gchar * purple_http_response_get_error(PurpleHttpResponse *response);

/**
 * Gets HTTP response data length.
 *
 * @param response The response.
 * @return         Data length;
 */
gsize purple_http_response_get_data_len(PurpleHttpResponse *response);

/**
 * Gets HTTP response data.
 *
 * Response data is not written, if writer callback was set for request.
 *
 * @param response The response.
 * @param len      Return address for the size of the data.  Can be NULL.
 * @return         The data.
 */
const gchar * purple_http_response_get_data(PurpleHttpResponse *response, size_t *len);

/**
 * Gets all headers got with response.
 *
 * @param response The response.
 * @return         GList of PurpleKeyValuePair, which keys are header field
 *                 names (gchar*) and values are its contents (gchar*).
 */
const GList * purple_http_response_get_all_headers(PurpleHttpResponse *response);

/**
 * Gets all headers with specified name got with response.
 *
 * @param response The response.
 * @param name     The name of header field.
 * @return         GList of header field records contents (gchar*).
 */
const GList * purple_http_response_get_headers_by_name(
	PurpleHttpResponse *response, const gchar *name);

/**
 * Gets one header contents with specified name got with response.
 *
 * To get all headers with the same name, use
 * purple_http_response_get_headers_by_name instead.
 *
 * @param response The response.
 * @param name     The name of header field.
 * @return         Header field contents or NULL, if there is no such one.
 */
const gchar * purple_http_response_get_header(PurpleHttpResponse *response,
	const gchar *name);

/*@}*/


/**************************************************************************/
/** @name HTTP Subsystem                                                  */
/**************************************************************************/
/*@{*/

/**
 * Initializes the http subsystem.
 */
void purple_http_init(void);

/**
 * Uninitializes the http subsystem.
 */
void purple_http_uninit(void);

/*@}*/

G_END_DECLS

#endif /* _PURPLE_HTTP_H_ */
