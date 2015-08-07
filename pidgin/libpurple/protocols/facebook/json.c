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
#include <string.h>

#include "json.h"
#include "util.h"

GQuark
fb_json_error_quark(void)
{
	static GQuark q = 0;

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
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

	json_builder_add_boolean_value(bldr, value);
}

void
fb_json_bldr_add_dbl(JsonBuilder *bldr, const gchar *name, gdouble value)
{
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

	json_builder_add_double_value(bldr, value);
}

void
fb_json_bldr_add_int(JsonBuilder *bldr, const gchar *name, gint64 value)
{
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

	json_builder_add_int_value(bldr, value);
}

void
fb_json_bldr_add_str(JsonBuilder *bldr, const gchar *name, const gchar *value)
{
	if (name != NULL) {
		json_builder_set_member_name(bldr, name);
	}

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

	fb_json_bldr_add_str(bldr, name, value);
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
		json_node_free(node);
		return NULL;
	}

	rslt = json_node_get_array(node);
	size = json_array_get_length(rslt);

	if (size < 1) {
		g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_NOMATCH,
		            _("No matches for %s"), expr);
		json_node_free(node);
		return NULL;
	}

	if (size > 1) {
		g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_AMBIGUOUS,
		            _("Ambiguous matches for %s"), expr);
		json_node_free(node);
		return NULL;
	}

	if (json_array_get_null_element(rslt, 0)) {
		g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_NULL,
		            _("Null value for %s"), expr);
		json_node_free(node);
		return NULL;
	}

	ret = json_array_dup_element(rslt, 0);
	json_node_free(node);
	return ret;
}

JsonNode *
fb_json_node_get_nth(JsonNode *root, guint n)
{
	GList *vals;
	JsonNode *ret;
	JsonObject *obj;

	obj = json_node_get_object(root);
	vals = json_object_get_values(obj);
	ret = g_list_nth_data(vals, n);

	g_list_free(vals);
	return ret;
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

	ret = json_node_dup_array(rslt);
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

gchar *
fb_json_node_get_str(JsonNode *root, const gchar *expr, GError **error)
{
	gchar *ret;
	JsonNode *rslt;

	rslt = fb_json_node_get(root, expr, error);

	if (rslt == NULL) {
		return NULL;
	}

	ret = json_node_dup_string(rslt);
	json_node_free(rslt);
	return ret;
}

FbJsonValues *
fb_json_values_new(JsonNode *root, const gchar *arrexpr)
{
	FbJsonValues *ret;

	g_return_val_if_fail(root != NULL, NULL);

	ret = g_new0(FbJsonValues, 1);
	ret->root = root;
	ret->queue = g_queue_new();

	if (arrexpr != NULL) {
		ret->array = fb_json_node_get_arr(root, arrexpr, &ret->error);
	}

	return ret;
}

void
fb_json_values_free(FbJsonValues *values)
{
	FbJsonValue *value;

	if (G_UNLIKELY(values == NULL)) {
		return;
	}

	while (!g_queue_is_empty(values->queue)) {
		value = g_queue_pop_head(values->queue);

		if (G_IS_VALUE(&value->value)) {
			g_value_unset(&value->value);
		}

		g_free(value);
	}

	if (values->array != NULL) {
		json_array_unref(values->array);
	}

	if (values->error != NULL) {
		g_error_free(values->error);
	}

	g_queue_free(values->queue);
	g_free(values);
}

void
fb_json_values_add(FbJsonValues *values, FbJsonType type, gboolean required,
                   const gchar *expr)
{
	FbJsonValue *value;

	g_return_if_fail(values != NULL);
	g_return_if_fail(expr != NULL);

	value = g_new0(FbJsonValue, 1);
	value->expr = expr;
	value->type = type;
	value->required = required;

	g_queue_push_tail(values->queue, value);
}

JsonNode *
fb_json_values_get_root(FbJsonValues *values)
{
	guint index;

	g_return_val_if_fail(values != NULL, NULL);

	if (values->array == NULL) {
		return values->root;
	}

	g_return_val_if_fail(values->array != NULL, NULL);
	g_return_val_if_fail(values->index > 0, NULL);
	index = values->index - 1;

	if (json_array_get_length(values->array) <= index) {
		return NULL;
	}

	return json_array_get_element(values->array, index);
}

gboolean
fb_json_values_update(FbJsonValues *values, GError **error)
{
	FbJsonValue *value;
	GError *err = NULL;
	GList *l;
	GType type;
	JsonNode *root;
	JsonNode *node;

	g_return_val_if_fail(values != NULL, FALSE);

	if (G_UNLIKELY(values->error != NULL)) {
		g_propagate_error(error, err);
		values->error = NULL;
		return FALSE;
	}

	if (values->array != NULL) {
		if (json_array_get_length(values->array) <= values->index) {
			return FALSE;
		}

		root = json_array_get_element(values->array, values->index++);
	} else {
		root = values->root;
	}

	g_return_val_if_fail(root != NULL, FALSE);

	for (l = values->queue->head; l != NULL; l = l->next) {
		value = l->data;
		node = fb_json_node_get(root, value->expr, &err);

		if (G_IS_VALUE(&value->value)) {
			g_value_unset(&value->value);
		}

		if (err != NULL) {
			json_node_free(node);

			if (value->required) {
				g_propagate_error(error, err);
				return FALSE;
			}

			g_clear_error(&err);
			continue;
		}

		type = json_node_get_value_type(node);

		if (G_UNLIKELY(type != value->type)) {
			g_set_error(error, FB_JSON_ERROR, FB_JSON_ERROR_TYPE,
			            _("Expected a %s but got a %s for %s"),
			            g_type_name(value->type),
			            g_type_name(type),
				    value->expr);
			json_node_free(node);
			return FALSE;
		}

		json_node_get_value(node, &value->value);
		json_node_free(node);
	}

	values->next = values->queue->head;
	return TRUE;
}

const GValue *
fb_json_values_next(FbJsonValues *values)
{
	FbJsonValue *value;

	g_return_val_if_fail(values != NULL, NULL);
	g_return_val_if_fail(values->next != NULL, NULL);

	value = values->next->data;
	values->next = values->next->next;

	if (!G_IS_VALUE(&value->value)) {
		return NULL;
	}

	return &value->value;
}

gboolean
fb_json_values_next_bool(FbJsonValues *values, gboolean defval)
{
	const GValue *value;

	value = fb_json_values_next(values);

	if (G_UNLIKELY(value == NULL)) {
		return defval;
	}

	return g_value_get_boolean(value);
}

gdouble
fb_json_values_next_dbl(FbJsonValues *values, gdouble defval)
{
	const GValue *value;

	value = fb_json_values_next(values);

	if (G_UNLIKELY(value == NULL)) {
		return defval;
	}

	return g_value_get_double(value);
}

gint64
fb_json_values_next_int(FbJsonValues *values, gint64 defval)
{
	const GValue *value;

	value = fb_json_values_next(values);

	if (G_UNLIKELY(value == NULL)) {
		return defval;
	}

	return g_value_get_int64(value);
}

const gchar *
fb_json_values_next_str(FbJsonValues *values, const gchar *defval)
{
	const GValue *value;

	value = fb_json_values_next(values);

	if (G_UNLIKELY(value == NULL)) {
		return defval;
	}

	return g_value_get_string(value);
}

gchar *
fb_json_values_next_str_dup(FbJsonValues *values, const gchar *defval)
{
	const GValue *value;

	value = fb_json_values_next(values);

	if (G_UNLIKELY(value == NULL)) {
		return g_strdup(defval);
	}

	return g_value_dup_string(value);
}
