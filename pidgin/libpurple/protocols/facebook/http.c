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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"

#include <string.h>

#include "http.h"

struct _FbHttpConns
{
	GHashTable *cons;
	gboolean canceled;
};

GQuark
fb_http_error_quark(void)
{
	static GQuark q = 0;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-http-error-quark");
	}

	return q;
}

FbHttpConns *
fb_http_conns_new(void)
{
	FbHttpConns *cons;

	cons = g_new0(FbHttpConns, 1);
	cons->cons = g_hash_table_new(g_direct_hash, g_direct_equal);
	return cons;
}

void
fb_http_conns_free(FbHttpConns *cons)
{
	g_return_if_fail(cons != NULL);

	g_hash_table_destroy(cons->cons);
	g_free(cons);
}

void
fb_http_conns_cancel_all(FbHttpConns *cons)
{
	GHashTableIter iter;
	gpointer con;

	g_return_if_fail(cons != NULL);
	g_return_if_fail(!cons->canceled);

	cons->canceled = TRUE;
	g_hash_table_iter_init(&iter, cons->cons);

	while (g_hash_table_iter_next(&iter, &con, NULL)) {
		g_hash_table_iter_remove(&iter);
		purple_http_conn_cancel(con);
	}
}

gboolean
fb_http_conns_is_canceled(FbHttpConns *cons)
{
	g_return_val_if_fail(cons != NULL, TRUE);
	return cons->canceled;
}

void
fb_http_conns_add(FbHttpConns *cons, PurpleHttpConnection *con)
{
	g_return_if_fail(cons != NULL);
	g_return_if_fail(!cons->canceled);
	g_hash_table_replace(cons->cons, con, con);
}

void
fb_http_conns_remove(FbHttpConns *cons, PurpleHttpConnection *con)
{
	g_return_if_fail(cons != NULL);
	g_return_if_fail(!cons->canceled);
	g_hash_table_remove(cons->cons, con);
}

void
fb_http_conns_reset(FbHttpConns *cons)
{
	g_return_if_fail(cons != NULL);
	cons->canceled = FALSE;
	g_hash_table_remove_all(cons->cons);
}

gboolean
fb_http_error_chk(PurpleHttpResponse *res, GError **error)
{
	const gchar *msg;
	gint code;

	if (purple_http_response_is_successful(res)) {
		return TRUE;
	}

	msg = purple_http_response_get_error(res);
	code = purple_http_response_get_code(res);
	g_set_error(error, FB_HTTP_ERROR, code, "%s", msg);
	return FALSE;
}

FbHttpParams *
fb_http_params_new(void)
{
        return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

FbHttpParams *
fb_http_params_new_parse(const gchar *data, gboolean isurl)
{
	const gchar *tail;
	gchar *key;
	gchar **ps;
	gchar *val;
	guint i;
	FbHttpParams *params;

	params = fb_http_params_new();

	if (data == NULL) {
		return params;
	}

	if (isurl) {
		data = strchr(data, '?');

		if (data == NULL) {
			return params;
		}

		tail = strchr(++data, '#');

		if (tail != NULL) {
			data = g_strndup(data, tail - data);
		} else {
			data = g_strdup(data);
		}
	}

	ps = g_strsplit(data, "&", 0);

	for (i = 0; ps[i] != NULL; i++) {
		key = ps[i];
		val = strchr(ps[i], '=');

		if (val == NULL) {
			continue;
		}

		*(val++) = 0;
		key = g_uri_unescape_string(key, NULL);
		val = g_uri_unescape_string(val, NULL);
		g_hash_table_replace(params, key, val);
	}

	if (isurl) {
		g_free((gchar *) data);
	}

	g_strfreev(ps);
	return params;
}

void
fb_http_params_free(FbHttpParams *params)
{
	g_hash_table_destroy(params);
}

gchar *
fb_http_params_close(FbHttpParams *params, const gchar *url)
{
	GHashTableIter iter;
	gpointer key;
	gpointer val;
	GString *ret;

	g_hash_table_iter_init(&iter, params);
	ret = g_string_new(NULL);

	while (g_hash_table_iter_next(&iter, &key, &val)) {
		if (val == NULL) {
			g_hash_table_iter_remove(&iter);
			continue;
		}

		if (ret->len > 0) {
			g_string_append_c(ret, '&');
		}

		g_string_append_uri_escaped(ret, key, NULL, TRUE);
		g_string_append_c(ret, '=');
		g_string_append_uri_escaped(ret, val, NULL, TRUE);
	}

	if (url != NULL) {
		g_string_prepend_c(ret, '?');
		g_string_prepend(ret, url);
	}

	fb_http_params_free(params);
	return g_string_free(ret, FALSE);
}

static const gchar *
fb_http_params_get(FbHttpParams *params, const gchar *name, GError **error)
{
	const gchar *ret;

	ret = g_hash_table_lookup(params, name);

	if (ret == NULL) {
		g_set_error(error, FB_HTTP_ERROR, FB_HTTP_ERROR_NOMATCH,
		            _("No matches for %s"), name);
		return NULL;
	}

	return ret;
}

gboolean
fb_http_params_get_bool(FbHttpParams *params, const gchar *name,
                        GError **error)
{
	const gchar *val;

	val = fb_http_params_get(params, name, error);

	if (val == NULL) {
		return FALSE;
	}

	return g_ascii_strcasecmp(val, "TRUE") == 0;
}

gdouble
fb_http_params_get_dbl(FbHttpParams *params, const gchar *name,
                       GError **error)
{
	const gchar *val;

	val = fb_http_params_get(params, name, error);

	if (val == NULL) {
		return 0.0;
	}

	return g_ascii_strtod(val, NULL);
}

gint64
fb_http_params_get_int(FbHttpParams *params, const gchar *name,
                       GError **error)
{
	const gchar *val;

	val = fb_http_params_get(params, name, error);

	if (val == NULL) {
		return 0;
	}

	return g_ascii_strtoll(val, NULL, 10);
}

const gchar *
fb_http_params_get_str(FbHttpParams *params, const gchar *name,
                       GError **error)
{
	return fb_http_params_get(params, name, error);
}

gchar *
fb_http_params_dup_str(FbHttpParams *params, const gchar *name,
                       GError **error)
{
	const gchar *str;

	str = fb_http_params_get(params, name, error);
	return g_strdup(str);
}

static void
fb_http_params_set(FbHttpParams *params, const gchar *name, gchar *value)
{
	gchar *key;

	key = g_strdup(name);
	g_hash_table_replace(params, key, value);
}

void
fb_http_params_set_bool(FbHttpParams *params, const gchar *name,
                        gboolean value)
{
	gchar *val;

	val = g_strdup(value ? "true" : "false");
	fb_http_params_set(params, name, val);
}

void
fb_http_params_set_dbl(FbHttpParams *params, const gchar *name, gdouble value)
{
	gchar *val;

	val = g_strdup_printf("%f", value);
	fb_http_params_set(params, name, val);
}

void
fb_http_params_set_int(FbHttpParams *params, const gchar *name, gint64 value)
{
	gchar *val;

	val = g_strdup_printf("%" G_GINT64_FORMAT, value);
	fb_http_params_set(params, name, val);
}

void
fb_http_params_set_str(FbHttpParams *params, const gchar *name,
                       const gchar *value)
{
	gchar *val;

	val = g_strdup(value);
	fb_http_params_set(params, name, val);
}

void
fb_http_params_set_strf(FbHttpParams *params, const gchar *name,
                        const gchar *format, ...)
{
	gchar *val;
	va_list ap;

	va_start(ap, format);
	val = g_strdup_vprintf(format, ap);
	va_end(ap);

	fb_http_params_set(params, name, val);
}

gboolean
fb_http_urlcmp(const gchar *url1, const gchar *url2, gboolean protocol)
{
	const gchar *str1;
	const gchar *str2;
	gboolean ret = TRUE;
	gint int1;
	gint int2;
	guint i;
	PurpleHttpURL *purl1;
	PurpleHttpURL *purl2;

	static const const gchar * (*funcs[]) (const PurpleHttpURL *url) = {
		/* Always first so it can be skipped */
		purple_http_url_get_protocol,

		purple_http_url_get_fragment,
		purple_http_url_get_host,
		purple_http_url_get_password,
		purple_http_url_get_path,
		purple_http_url_get_username
	};

	if ((url1 == NULL) || (url2 == NULL)) {
		return url1 == url2;
	}

	purl1 = purple_http_url_parse(url1);

	if (purl1 == NULL) {
		return g_ascii_strcasecmp(url1, url2) == 0;
	}

	purl2 = purple_http_url_parse(url2);

	if (purl2 == NULL) {
		purple_http_url_free(purl1);
		return g_ascii_strcasecmp(url1, url2) == 0;
	}

	for (i = protocol ? 0 : 1; i < G_N_ELEMENTS(funcs); i++) {
		str1 = funcs[i](purl1);
		str2 = funcs[i](purl2);

		if (!purple_strequal(str1, str2)) {
			ret = FALSE;
			break;
		}
	}

	if (ret && protocol) {
		int1 = purple_http_url_get_port(purl1);
		int2 = purple_http_url_get_port(purl2);

		if (int1 != int2) {
			ret = FALSE;
		}
	}

	purple_http_url_free(purl1);
	purple_http_url_free(purl2);
	return ret;
}
