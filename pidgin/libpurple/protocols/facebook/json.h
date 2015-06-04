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

enum _FbJsonError
{
	FB_JSON_ERROR_SUCCESS = 0,
	FB_JSON_ERROR_AMBIGUOUS,
	FB_JSON_ERROR_NOMATCH
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

JsonArray *
fb_json_node_get_arr(JsonNode *root, const gchar *expr, GError **error);

gboolean
fb_json_node_get_bool(JsonNode *root, const gchar *expr, GError **error);

gdouble
fb_json_node_get_dbl(JsonNode *root, const gchar *expr, GError **error);

gint64
fb_json_node_get_int(JsonNode *root, const gchar *expr, GError **error);

const gchar *
fb_json_node_get_str(JsonNode *root, const gchar *expr, GError **error);

gboolean
fb_json_node_chk(JsonNode *root, const gchar *expr, JsonNode **value);

gboolean
fb_json_node_chk_arr(JsonNode *root, const gchar *expr, JsonArray **value);

gboolean
fb_json_node_chk_bool(JsonNode *root, const gchar *expr, gboolean *value);

gboolean
fb_json_node_chk_dbl(JsonNode *root, const gchar *expr, gdouble *value);

gboolean
fb_json_node_chk_int(JsonNode *root, const gchar *expr, gint64 *value);

gboolean
fb_json_node_chk_str(JsonNode *root, const gchar *expr, const gchar **value);

#endif /* _FACEBOOK_JSON_H_ */
