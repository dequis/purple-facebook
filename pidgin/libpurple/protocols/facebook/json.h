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

#ifndef _FACEBOOK_JSON_H_
#define _FACEBOOK_JSON_H_

#include <glib.h>
#include <json-glib/json-glib.h>

#define FB_JSON_ERROR fb_json_error_quark()

typedef enum _FbJsonError FbJsonError;
typedef struct _FbJsonValue FbJsonValue;
typedef struct _FbJsonValues FbJsonValues;

enum _FbJsonError
{
	FB_JSON_ERROR_SUCCESS = 0,
	FB_JSON_ERROR_AMBIGUOUS,
	FB_JSON_ERROR_GENERAL,
	FB_JSON_ERROR_NOMATCH,
	FB_JSON_ERROR_NULL
};

struct _FbJsonValue
{
	const gchar *expr;
	gboolean required;
	GValue value;
};

struct _FbJsonValues
{
	JsonNode *root;
	GQueue *queue;
	GList *next;
	JsonArray *array;
	guint index;
	gboolean success;
};

GQuark
fb_json_error_quark(void);

JsonBuilder *
fb_json_bldr_new(JsonNodeType type);

gchar *
fb_json_bldr_close(JsonBuilder *bldr, JsonNodeType type, gsize *size);

void
fb_json_bldr_arr_begin(JsonBuilder *bldr, const gchar *name);

void
fb_json_bldr_arr_end(JsonBuilder *bldr);

void
fb_json_bldr_obj_begin(JsonBuilder *bldr, const gchar *name);

void
fb_json_bldr_obj_end(JsonBuilder *bldr);

void
fb_json_bldr_add_bool(JsonBuilder *bldr, const gchar *name, gboolean value);

void
fb_json_bldr_add_dbl(JsonBuilder *bldr, const gchar *name, gdouble value);

void
fb_json_bldr_add_int(JsonBuilder *bldr, const gchar *name, gint64 value);

void
fb_json_bldr_add_str(JsonBuilder *bldr, const gchar *name, const gchar *value);

void
fb_json_bldr_add_strf(JsonBuilder *bldr, const gchar *name,
                      const gchar *format, ...)
                      G_GNUC_PRINTF(3, 4);

JsonNode *
fb_json_node_new(const gchar *data, gssize size, GError **error);

JsonNode *
fb_json_node_get(JsonNode *root, const gchar *expr, GError **error);

JsonNode *
fb_json_node_get_nth(JsonNode *root, guint n);

JsonArray *
fb_json_node_get_arr(JsonNode *root, const gchar *expr, GError **error);

gboolean
fb_json_node_get_bool(JsonNode *root, const gchar *expr, GError **error);

gdouble
fb_json_node_get_dbl(JsonNode *root, const gchar *expr, GError **error);

gint64
fb_json_node_get_int(JsonNode *root, const gchar *expr, GError **error);

gchar *
fb_json_node_get_str(JsonNode *root, const gchar *expr, GError **error);

FbJsonValues *
fb_json_values_new(JsonNode *root);

void
fb_json_values_free(FbJsonValues *values);

void
fb_json_values_add(FbJsonValues *values, gboolean required, const gchar *expr);

JsonNode *
fb_json_values_get_root(FbJsonValues *values);

void
fb_json_values_set_array(FbJsonValues *values, const gchar *expr,
                         GError **error);

gboolean
fb_json_values_successful(FbJsonValues *values);

gboolean
fb_json_values_update(FbJsonValues *values, GError **error);

const GValue *
fb_json_values_next(FbJsonValues *values, GType type);

gboolean
fb_json_values_next_bool(FbJsonValues *values, gboolean defval);

gdouble
fb_json_values_next_dbl(FbJsonValues *values, gdouble defval);

gint64
fb_json_values_next_int(FbJsonValues *values, gint64 defval);

const gchar *
fb_json_values_next_str(FbJsonValues *values, const gchar *defval);

gchar *
fb_json_values_next_str_dup(FbJsonValues *values, const gchar *defval);

#endif /* _FACEBOOK_JSON_H_ */
