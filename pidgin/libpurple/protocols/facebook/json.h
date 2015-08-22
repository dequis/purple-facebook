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

/**
 * SECTION:json
 * @section_id: facebook-json
 * @short_description: <filename>json.h</filename>
 * @title: JSON Utilities
 *
 * The JSON utilities.
 */

#include <glib.h>
#include <json-glib/json-glib.h>

#define FB_TYPE_JSON_VALUES  (fb_json_values_get_type())
#define FB_JSON_VALUES(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_JSON_VALUES, FbJsonValues))
#define FB_JSON_VALUES_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_JSON_VALUES, FbJsonValuesClass))
#define FB_IS_JSON_VALUES(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_JSON_VALUES))
#define FB_IS_JSON_VALUES_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_JSON_VALUES))
#define FB_JSON_VALUES_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_JSON_VALUES, FbJsonValuesClass))

/**
 * FB_JSON_ERROR:
 *
 * The #GQuark of the domain of JSON errors.
 */
#define FB_JSON_ERROR fb_json_error_quark()

typedef struct _FbJsonValues FbJsonValues;
typedef struct _FbJsonValuesClass FbJsonValuesClass;
typedef struct _FbJsonValuesPrivate FbJsonValuesPrivate;

/**
 * FbJsonError:
 * @FB_JSON_ERROR_SUCCESS: There is no error.
 * @FB_JSON_ERROR_AMBIGUOUS: The node has ambiguous matches.
 * @FB_JSON_ERROR_GENERAL: General failure.
 * @FB_JSON_ERROR_NOMATCH: The node does not match anything.
 * @FB_JSON_ERROR_NULL: The node is of type NULL.
 * @FB_JSON_ERROR_TYPE: The node has an unexpected type.
 *
 * The error codes for the #FB_JSON_ERROR domain.
 */
typedef enum
{
	FB_JSON_ERROR_SUCCESS = 0,
	FB_JSON_ERROR_AMBIGUOUS,
	FB_JSON_ERROR_GENERAL,
	FB_JSON_ERROR_NOMATCH,
	FB_JSON_ERROR_NULL,
	FB_JSON_ERROR_TYPE
} FbJsonError;

/**
 * FbJsonType:
 * @FB_JSON_TYPE_NULL: An unknown value.
 * @FB_JSON_TYPE_BOOL: A boolean (#TRUE or #FALSE).
 * @FB_JSON_TYPE_DBL: A floating point number.
 * @FB_JSON_TYPE_INT: A signed integer.
 * @FB_JSON_TYPE_STR: A string.
 *
 * The JSON data types.
 */
typedef enum
{
	FB_JSON_TYPE_NULL = 0,
	FB_JSON_TYPE_BOOL = G_TYPE_BOOLEAN,
	FB_JSON_TYPE_DBL = G_TYPE_DOUBLE,
	FB_JSON_TYPE_INT = G_TYPE_INT64,
	FB_JSON_TYPE_STR = G_TYPE_STRING
} FbJsonType;

/**
 * FbJsonValues:
 *
 * Represents a JSON value handler.
 */
struct _FbJsonValues
{
	/*< private >*/
	GObject parent;
	FbJsonValuesPrivate *priv;
};

/**
 * FbJsonValuesClass:
 *
 * The base class for all #FbJsonValues's.
 */
struct _FbJsonValuesClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * fb_json_values_get_type:
 *
 * Returns: The #GType for an #FbJsonValues.
 */
GType
fb_json_values_get_type(void);

/**
 * fb_json_error_quark:
 *
 * Gets the #GQuark of the domain of JSON errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_json_error_quark(void);

/**
 * fb_json_bldr_new:
 * @type: The starting #JsonNodeType.
 *
 * Creates a new #JsonBuilder. The starting #JsonNodeType is likely to
 * be #JSON_NODE_OBJECT. The returned #JsonBuilder should be freed with
 * #g_object_unref() when no longer needed. Optionally, instead of
 * freeing, the returned #JsonBuilder can be closed with
 * #fb_json_bldr_close().
 *
 * Returns: The new #JsonBuilder.
 */
JsonBuilder *
fb_json_bldr_new(JsonNodeType type);

/**
 * fb_json_bldr_close:
 * @bldr: The #JsonBuilder.
 * @type: The ending #JsonNodeType.
 * @size: The return local for the size of the returned string.
 *
 * Closes the #JsonBuilder by returning a string representing the
 * #JsonBuilder. The ending #JsonNodeType is likely to be
 * #JSON_NODE_OBJECT. This calls #g_object_unref(). The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The string representation of the #JsonBuilder.
 */
gchar *
fb_json_bldr_close(JsonBuilder *bldr, JsonNodeType type, gsize *size);

/**
 * fb_json_bldr_arr_begin:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 *
 * Begins an array member in the #JsonBuilder.
 */
void
fb_json_bldr_arr_begin(JsonBuilder *bldr, const gchar *name);

/**
 * fb_json_bldr_arr_end:
 * @bldr: The #JsonBuilder.
 *
 * Ends an array member in the #JsonBuilder.
 */
void
fb_json_bldr_arr_end(JsonBuilder *bldr);

/**
 * fb_json_bldr_obj_begin:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 *
 * Begins an object member in the #JsonBuilder.
 */
void
fb_json_bldr_obj_begin(JsonBuilder *bldr, const gchar *name);

/**
 * fb_json_bldr_obj_end:
 * @bldr: The #JsonBuilder.
 *
 * Ends an array member in the #JsonBuilder.
 */
void
fb_json_bldr_obj_end(JsonBuilder *bldr);

/**
 * fb_json_bldr_add_bool:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 * @value: The value.
 *
 * Adds a boolean memeber to the #JsonBuilder.
 */
void
fb_json_bldr_add_bool(JsonBuilder *bldr, const gchar *name, gboolean value);

/**
 * fb_json_bldr_add_dbl:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 * @value: The value.
 *
 * Adds a floating point memeber to the #JsonBuilder.
 */
void
fb_json_bldr_add_dbl(JsonBuilder *bldr, const gchar *name, gdouble value);

/**
 * fb_json_bldr_add_int:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 * @value: The value.
 *
 * Adds a integer memeber to the #JsonBuilder.
 */
void
fb_json_bldr_add_int(JsonBuilder *bldr, const gchar *name, gint64 value);

/**
 * fb_json_bldr_add_str:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 * @value: The value.
 *
 * Adds a string memeber to the #JsonBuilder.
 */
void
fb_json_bldr_add_str(JsonBuilder *bldr, const gchar *name, const gchar *value);

/**
 * fb_json_bldr_add_strf:
 * @bldr: The #JsonBuilder.
 * @name: The member name, or #NULL.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Adds a formatted string memeber to the #JsonBuilder.
 */
void
fb_json_bldr_add_strf(JsonBuilder *bldr, const gchar *name,
                      const gchar *format, ...)
                      G_GNUC_PRINTF(3, 4);

/**
 * fb_json_node_new:
 * @data: The string JSON.
 * @size: The size of @json, or -1 if null-terminated.
 * @error: The return location for the #GError, or #NULL.
 *
 * Creates a new #JsonNode. The returned #JsonBuilder should be freed
 * wuth #json_node_free() when no longer needed.
 *
 * Returns: The new #JsonNode.
 */
JsonNode *
fb_json_node_new(const gchar *data, gssize size, GError **error);

/**
 * fb_json_node_get:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets a new #JsonNode value from a parent #JsonNode with a #JsonPath
 * expression. The returned #JsonNode should be freed with
 * #json_node_free() when no longer needed.
 *
 * Returns: The new #JsonNode.
 */
JsonNode *
fb_json_node_get(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_node_get_nth:
 * @root: The root #JsonNode.
 * @n: The index number.
 *
 * Gets a #JsonNode value from a parent #JsonNode by index. The
 * returned #JsonNode should not be freed.
 *
 * Return: The #JsonNode.
 */
JsonNode *
fb_json_node_get_nth(JsonNode *root, guint n);

/**
 * fb_json_node_get_arr:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets a new #JsonArray value from a parent #JsonNode with a #JsonPath
 * expression. The returned #JsonArray should be freed with
 * #json_array_unref() when no longer needed.
 *
 * Returns: The new #JsonArray.
 */
JsonArray *
fb_json_node_get_arr(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_node_get_bool:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets a boolean value from a parent #JsonNode with a #JsonPath
 * expression.
 *
 * Returns: The boolean value.
 */
gboolean
fb_json_node_get_bool(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_node_get_dbl:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets a floating point value from a parent #JsonNode with a #JsonPath
 * expression.
 *
 * Returns: The floating point value.
 */
gdouble
fb_json_node_get_dbl(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_node_get_int:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets an integer value from a parent #JsonNode with a #JsonPath
 * expression.
 *
 * Returns: The integer value.
 */
gint64
fb_json_node_get_int(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_node_get_str:
 * @root: The root #JsonNode.
 * @expr: The #JsonPath expression.
 * @error: The return location for the #GError, or #NULL.
 *
 * Gets an string value from a parent #JsonNode with a #JsonPath
 * expression. The returned string should be freed with #g_free()
 * when no longer needed.
 *
 * Returns: The string value.
 */
gchar *
fb_json_node_get_str(JsonNode *root, const gchar *expr, GError **error);

/**
 * fb_json_values_new:
 * @root: The root #JsonNode.
 *
 * Creates a new #FbJsonValues. The returned #FbJsonValues should be
 * freed with #g_object_unref when no longer needed.
 *
 * Returns: The new #FbJsonValues.
 */
FbJsonValues *
fb_json_values_new(JsonNode *root);

/**
 * fb_json_values_add:
 * @values: The #FbJsonValues.
 * @type: The #FbJsonType.
 * @required: TRUE if the node is required, otherwise FALSE.
 * @expr: The #JsonPath expression.
 *
 * Adds a new #FbJsonValue to the #FbJsonValues.
 */
void
fb_json_values_add(FbJsonValues *values, FbJsonType type, gboolean required,
                   const gchar *expr);

/**
 * fb_json_values_get_root:
 * @values: The #FbJsonValues.
 *
 * Gets the current working root #JsonNode. This is either the current
 * array #JsonNode, or the root #JsonNode. The returned #JsonNode
 * should not be freed.
 */
JsonNode *
fb_json_values_get_root(FbJsonValues *values);

/**
 * fb_json_values_set_array:
 * @values: The #FbJsonValues.
 * @required: TRUE if the node is required, otherwise FALSE.
 * @expr: The #JsonPath expression.
 *
 * Sets the #JsonPath for an array to base all #FbJsonValue's off.
 */
void
fb_json_values_set_array(FbJsonValues *values, gboolean required,
                         const gchar *expr);

/**
 * fb_json_values_update:
 * @values: The #FbJsonValues.
 * @error: The return location for the #GError, or #NULL.
 *
 * Updates the current working root. This should be called after all of
 * the #FbJsonValue's have been added with #fb_json_values_add(). If an
 * array was set with #fb_json_values_set_array(), then this should be
 * called in a while loop, until #FALSE is returned.
 *
 * Returns: #TRUE if the values were updated, otherwise #FALSE.
 */
gboolean
fb_json_values_update(FbJsonValues *values, GError **error);

/**
 * fb_json_values_next:
 * @values: The #FbJsonValues.
 *
 * Gets the next #GValue from the #FbJsonValues. Before calling this
 * function, #fb_json_values_update() must be called.
 *
 * Returns: The #GValue.
 */
const GValue *
fb_json_values_next(FbJsonValues *values);

/**
 * fb_json_values_next_bool:
 * @values: The #FbJsonValues.
 * @defval: The default value.
 *
 * Gets the next boolean value from the #FbJsonValues. Before calling
 * this function, #fb_json_values_update() must be called.
 *
 * Returns: The boolean value.
 */
gboolean
fb_json_values_next_bool(FbJsonValues *values, gboolean defval);

/**
 * fb_json_values_next_dbl:
 * @values: The #FbJsonValues.
 * @defval: The default value.
 *
 * Gets the next floating point value from the #FbJsonValues. Before
 * calling this function, #fb_json_values_update() must be called.
 *
 * Returns: The floating point value.
 */
gdouble
fb_json_values_next_dbl(FbJsonValues *values, gdouble defval);

/**
 * fb_json_values_next_int:
 * @values: The #FbJsonValues.
 * @defval: The default value.
 *
 * Gets the next integer value from the #FbJsonValues. Before calling
 * this function, #fb_json_values_update() must be called.
 *
 * Returns: The integer value.
 */
gint64
fb_json_values_next_int(FbJsonValues *values, gint64 defval);

/**
 * fb_json_values_next_str:
 * @values: The #FbJsonValues.
 * @defval: The default value.
 *
 * Gets the next string value from the #FbJsonValues. Before calling
 * this function, #fb_json_values_update() must be called.
 *
 * Returns: The string value.
 */
const gchar *
fb_json_values_next_str(FbJsonValues *values, const gchar *defval);

/**
 * fb_json_values_next_str_dup:
 * @values: The #FbJsonValues.
 * @defval: The default value.
 *
 * Gets the next duplicate string value from the #FbJsonValues. Before
 * calling this function, #fb_json_values_update() must be called.
 *
 * Returns: The duplicate string value.
 */
gchar *
fb_json_values_next_str_dup(FbJsonValues *values, const gchar *defval);

#endif /* _FACEBOOK_JSON_H_ */
