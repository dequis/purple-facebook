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

#include <stdarg.h>

#include "json.h"

GQuark
fb_json_error_quark(void)
{
	static GQuark q;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-json-error-quark");
	}

	return q;
}

JsonBuilder *
fb_json_bldr_new(JsonNodeType type)
{
	JsonBuilder *bldr;

	bldr = json_builder_new();

	switch (type) {
	case JSON_NODE_ARRAY:
		fb_json_bldr_arr_begin(bldr, NULL);
		break;

	case JSON_NODE_OBJECT:
		fb_json_bldr_obj_begin(bldr, NULL);
		break;

	default:
		break;
	}

	return bldr;
}

gchar *
fb_json_bldr_close(JsonBuilder *bldr, JsonNodeType type, gsize *size)
{
	gchar *ret;
	JsonGenerator *genr;
	JsonNode *root;

	switch (type) {
	case JSON_NODE_ARRAY:
		fb_json_bldr_arr_end(bldr);
		break;

	case JSON_NODE_OBJECT:
		fb_json_bldr_obj_end(bldr);
		break;

	default:
		break;
	}

	genr = json_generator_new();
	root = json_builder_get_root(bldr);

	json_generator_set_root(genr, root);
	ret = json_generator_to_data(genr, size);

	json_node_free(root);
	g_object_unref(genr);
	g_object_unref(bldr);

	return ret;
}

void
fb_json_bldr_arr_begin(JsonBuilder *bldr, const gchar *name)
{
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

	json_builder_begin_array(bldr);
}

void
fb_json_bldr_arr_end(JsonBuilder *bldr)
{
	json_builder_end_array(bldr);
}

void
fb_json_bldr_obj_begin(JsonBuilder *bldr, const gchar *name)
{
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

	json_builder_begin_object(bldr);
}

void
fb_json_bldr_obj_end(JsonBuilder *bldr)
{
	json_builder_end_object(bldr);
}

void
fb_json_bldr_add_bool(JsonBuilder *bldr, const gchar *name, gboolean value)
{
	json_builder_set_member_name(bldr, name);
	json_builder_add_boolean_value(bldr, value);
}

void
fb_json_bldr_add_dbl(JsonBuilder *bldr, const gchar *name, gdouble value)
{
	json_builder_set_member_name(bldr, name);
	json_builder_add_double_value(bldr, value);
}

void
fb_json_bldr_add_int(JsonBuilder *bldr, const gchar *name, gint64 value)
{
	json_builder_set_member_name(bldr, name);
	json_builder_add_int_value(bldr, value);
}

void
fb_json_bldr_add_str(JsonBuilder *bldr, const gchar *name, const gchar *value)
{
	json_builder_set_member_name(bldr, name);
	json_builder_add_string_value(bldr, value);
}

void
fb_json_bldr_add_strf(JsonBuilder *bldr, const gchar *name,
					  const gchar *format, ...)
{
	gchar *value;
	va_list ap;

	va_start(ap, format);
	value = g_strdup_vprintf(format, ap);
	va_end(ap);

	json_builder_set_member_name(bldr, name);
	json_builder_add_string_value(bldr, value);

	g_free(value);
}

JsonNode *
fb_json_node_new(const gchar *data, gssize size, GError **error)
{
	JsonNode *root;
	JsonParser *prsr;

	prsr = json_parser_new();

	if (!json_parser_load_from_data(prsr, data, size, error)) {
		g_object_unref(prsr);
		return NULL;
	}

	root = json_parser_get_root(prsr);
	root = json_node_copy(root);

	g_object_unref(prsr);
	return root;
}

JsonNode *
fb_json_node_get(JsonNode *root, const gchar *expr, GError **error)
{
	GError *err = NULL;
	guint size;
	JsonArray *rslt;
	JsonNode *node;
	JsonNode *ret;

	node = json_path_query(expr, root, &err);

	if (err != NULL) {
		g_propagate_error(error, err);
		goto error;
	}

	rslt = json_node_get_array(node);
	size = json_array_get_length(rslt);

	if (size < 1) {
		g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_NOMATCH,
		            _("No matches for %s"), expr);
		goto error;
	}

	if (size > 1) {
		g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_AMBIGUOUS,
		            _("Ambiguous matches for %s"), expr);
		goto error;
	}

	ret = json_array_dup_element(rslt, 0);
	json_node_free(node);
	return ret;

error:
	json_node_free(node);
	return NULL;
}

JsonArray *
fb_json_node_get_arr(JsonNode *root, const gchar *expr, GError **error)
{
	JsonArray *ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return NULL;
	}

	ret = json_node_get_array(rslt);
	json_node_free(rslt);
	return ret;
}

gboolean
fb_json_node_get_bool(JsonNode *root, const gchar *expr, GError **error)
{
	gboolean ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return FALSE;
	}

	ret = json_node_get_boolean(rslt);
	json_node_free(rslt);
	return ret;
}

gdouble
fb_json_node_get_dbl(JsonNode *root, const gchar *expr, GError **error)
{
	gdouble ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return 0.0;
	}

	ret = json_node_get_double(rslt);
	json_node_free(rslt);
	return ret;
}

gint64
fb_json_node_get_int(JsonNode *root, const gchar *expr, GError **error)
{
	gint64 ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return 0;
	}

	ret = json_node_get_int(rslt);
	json_node_free(rslt);
	return ret;
}

const gchar *
fb_json_node_get_str(JsonNode *root, const gchar *expr, GError **error)
{
	const gchar *ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return NULL;
	}

	ret = json_node_get_string(rslt);
	json_node_free(rslt);
	return ret;
}

gboolean
fb_json_node_chk(JsonNode *root, const gchar *expr, JsonNode **value)
{
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, NULL);

	if (rslt == NULL) {
		return FALSE;
	}

	if (value != NULL) {
		*value = rslt;
	}

	return TRUE;
}

gboolean
fb_json_node_chk_arr(JsonNode *root, const gchar *expr, JsonArray **value)
{
	JsonNode *rslt;

	if (!fb_json_node_chk(root, expr, &rslt)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = json_node_get_array(rslt);
	}

	json_node_free(rslt);
	return TRUE;
}

gboolean
fb_json_node_chk_bool(JsonNode *root, const gchar *expr, gboolean *value)
{
	JsonNode *rslt;

	if (!fb_json_node_chk(root, expr, &rslt)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = json_node_get_boolean(rslt);
	}

	json_node_free(rslt);
	return TRUE;
}

gboolean
fb_json_node_chk_dbl(JsonNode *root, const gchar *expr, gdouble *value)
{
	JsonNode *rslt;

	if (!fb_json_node_chk(root, expr, &rslt)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = json_node_get_double(rslt);
	}

	json_node_free(rslt);
	return TRUE;
}

gboolean
fb_json_node_chk_int(JsonNode *root, const gchar *expr, gint64 *value)
{
	JsonNode *rslt;

	if (!fb_json_node_chk(root, expr, &rslt)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = json_node_get_int(rslt);
	}

	json_node_free(rslt);
	return TRUE;
}

gboolean
fb_json_node_chk_str(JsonNode *root, const gchar *expr, const gchar **value)
{
	JsonNode *rslt;

	if (!fb_json_node_chk(root, expr, &rslt)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = json_node_get_string(rslt);
	}

	json_node_free(rslt);
	return TRUE;
}
