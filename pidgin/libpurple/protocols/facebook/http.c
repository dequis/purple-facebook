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

#include "http.h"

GQuark
fb_http_error_quark(void)
{
	static GQuark q;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-http-error-quark");
	}

	return q;
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

gchar *
fb_http_params_close(FbHttpParams *params, gsize *size)
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

	if (size != NULL) {
		*size = ret->len;
	}

	g_hash_table_destroy(params);
	return g_string_free(ret, FALSE);
}

static void
fb_http_params_insert(FbHttpParams *params, const gchar *name, gchar *value)
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
	fb_http_params_insert(params, name, val);
}

void
fb_http_params_set_dbl(FbHttpParams *params, const gchar *name, gdouble value)
{
	gchar *val;

	val = g_strdup_printf("%f", value);
	fb_http_params_insert(params, name, val);
}

void
fb_http_params_set_int(FbHttpParams *params, const gchar *name, gint64 value)
{
	gchar *val;

	val = g_strdup_printf("%" G_GINT64_FORMAT, value);
	fb_http_params_insert(params, name, val);
}

void
fb_http_params_set_str(FbHttpParams *params, const gchar *name,
                       const gchar *value)
{
	gchar *val;

	val = g_strdup(value);
	fb_http_params_insert(params, name, val);
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

	fb_http_params_insert(params, name, val);
}
