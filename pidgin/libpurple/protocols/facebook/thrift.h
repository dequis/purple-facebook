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

#ifndef _FACEBOOK_THRIFT_H_
#define _FACEBOOK_THRIFT_H_

/**
 * SECTION:thrift
 * @section_id: facebook-thrift
 * @short_description: <filename>thrift.h</filename>
 * @title: Thrift Reader/Writer
 *
 * The Thrift reader/writer.
 */

#include <glib.h>
#include <glib-object.h>

#define FB_TYPE_THRIFT  (fb_thrift_get_type())
#define FB_THRIFT(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_THRIFT, FbThrift))
#define FB_THRIFT_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_THRIFT, FbThriftClass))
#define FB_IS_THRIFT(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_THRIFT))
#define FB_IS_THRIFT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_THRIFT))
#define FB_THRIFT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_THRIFT, FbThriftClass))

typedef struct _FbThrift FbThrift;
typedef struct _FbThriftClass FbThriftClass;
typedef struct _FbThriftPrivate FbThriftPrivate;

/**
 * FbThriftType:
 * @FB_THRIFT_TYPE_STOP: A stopper for certain types.
 * @FB_THRIFT_TYPE_VOID: A void or empty value.
 * @FB_THRIFT_TYPE_BOOL: A boolean (#TRUE or #FALSE).
 * @FB_THRIFT_TYPE_BYTE: A signed 8-bit integer.
 * @FB_THRIFT_TYPE_DOUBLE: A 64-bit floating point number.
 * @FB_THRIFT_TYPE_I16: A signed 16-bit integer.
 * @FB_THRIFT_TYPE_I32: A signed 32-bit integer.
 * @FB_THRIFT_TYPE_I64: A signed 64-bit integer.
 * @FB_THRIFT_TYPE_STRING: A UTF-8 encoded string.
 * @FB_THRIFT_TYPE_STRUCT: A set of typed fields.
 * @FB_THRIFT_TYPE_MAP: A map of unique keys to values.
 * @FB_THRIFT_TYPE_SET: A unique set of values.
 * @FB_THRIFT_TYPE_LIST: A ordered list of values.
 * @FB_THRIFT_TYPE_ENUM: A 32-bit enumerated list.
 * @FB_THRIFT_TYPE_UNKNOWN: An unknown type.
 *
 * The Thrift data types.
 */
typedef enum
{
	FB_THRIFT_TYPE_STOP = 0,
	FB_THRIFT_TYPE_VOID = 1,
	FB_THRIFT_TYPE_BOOL = 2,
	FB_THRIFT_TYPE_BYTE = 3,
	FB_THRIFT_TYPE_DOUBLE = 4,
	FB_THRIFT_TYPE_I16 = 6,
	FB_THRIFT_TYPE_I32 = 8,
	FB_THRIFT_TYPE_I64 = 10,
	FB_THRIFT_TYPE_STRING = 11,
	FB_THRIFT_TYPE_STRUCT = 12,
	FB_THRIFT_TYPE_MAP = 13,
	FB_THRIFT_TYPE_SET = 14,
	FB_THRIFT_TYPE_LIST = 15,
	FB_THRIFT_TYPE_ENUM = 16,

	FB_THRIFT_TYPE_UNKNOWN
} FbThriftType;

/**
 * FbThrift:
 *
 * Represents a reader/writer for compact Thrift data.
 */
struct _FbThrift
{
	/*< private >*/
	GObject parent;
	FbThriftPrivate *priv;
};

/**
 * FbThriftClass:
 *
 * The base class for all #FbThrift's.
 */
struct _FbThriftClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * fb_thrift_get_type:
 *
 * Returns: The #GType for an #FbThrift.
 */
GType
fb_thrift_get_type(void);

/**
 * fb_thrift_new:
 * @bytes: The #GByteArray to read or write.
 * @offset: The offset in bytes of the data in @bytes.
 *
 * Creates a new #FbThrift. The returned #FbThrift should be freed with
 * #g_object_unref() when no longer needed. This will optionally use a
 * #GByteArray at an offset, rather than a newly created and internal
 * #GByteArray.
 *
 * Returns: The new #FbThrift.
 */
FbThrift *
fb_thrift_new(GByteArray *bytes, guint offset);

/**
 * fb_thrift_get_bytes:
 * @thft: The #FbThrift.
 *
 * Gets the underlying #GByteArray of an #FbThrift.
 *
 * Returns: The #GByteArray.
 */
const GByteArray *
fb_thrift_get_bytes(FbThrift *thft);

/**
 * fb_thrift_get_pos:
 * @thft: The #FbThrift.
 *
 * Gets the cursor position of an #FbThrift.
 *
 * Returns: The cursor position.
 */
guint
fb_thrift_get_pos(FbThrift *thft);

/**
 * fb_thrift_set_pos:
 * @thft: The #FbThrift.
 * @pos: The position.
 *
 * Sets the cursor position of an #FbThrift.
 *
 * Returns: The #GByteArray.
 */
void
fb_thrift_set_pos(FbThrift *thft, guint pos);

/**
 * fb_thrift_reset:
 * @thft: The #FbThrift.
 *
 * Resets the cursor position of an #FbThrift.
 *
 * Returns: The #GByteArray.
 */
void
fb_thrift_reset(FbThrift *thft);

/**
 * fb_thrift_read:
 * @thft: The #FbThrift.
 * @data: The data buffer.
 * @size: The size of @buffer.
 *
 * Reads data from the #FbThrift into a buffer. If @data is #NULL, this
 * will simply advance the cursor position.
 *
 * Returns: #TRUE if the data was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read(FbThrift *thft, gpointer data, guint size);

/**
 * fb_thrift_read_bool:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a boolean value from the #FbThrift. If @value is #NULL, this
 * will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_bool(FbThrift *thft, gboolean *value);

/**
 * fb_thrift_read_byte:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads an 8-bit integer value from the #FbThrift. If @value is #NULL,
 * this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_byte(FbThrift *thft, guint8 *value);

/**
 * fb_thrift_read_dbl:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a 64-bit floating point value from the #FbThrift. If @value
 * is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_dbl(FbThrift *thft, gdouble *value);

/**
 * fb_thrift_read_i16:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a signed 16-bit integer value from the #FbThrift. This will
 * convert the integer from the zig-zag format. If @value is #NULL,
 * this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_i16(FbThrift *thft, gint16 *value);

/**
 * fb_thrift_read_vi16:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a 16-bit integer value from the #FbThrift. This reads the raw
 * integer value without converting it from the zig-zag format. If
 * @value is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_vi16(FbThrift *thft, guint16 *value);

/**
 * fb_thrift_read_i32:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a signed 32-bit integer value from the #FbThrift. This will
 * convert the integer from the zig-zag format. If @value is #NULL,
 * this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_i32(FbThrift *thft, gint32 *value);

/**
 * fb_thrift_read_vi32:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a 32-bit integer value from the #FbThrift. This reads the raw
 * integer value without converting it from the zig-zag format. If
 * @value is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_vi32(FbThrift *thft, guint32 *value);

/**
 * fb_thrift_read_i64:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a signed 64-bit integer value from the #FbThrift. This will
 * convert the integer from the zig-zag format. If @value is #NULL,
 * this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_i64(FbThrift *thft, gint64 *value);

/**
 * fb_thrift_read_vi64:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a 64-bit integer value from the #FbThrift. This reads the raw
 * integer value without converting it from the zig-zag format. If
 * @value is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_vi64(FbThrift *thft, guint64 *value);

/**
 * fb_thrift_read_str:
 * @thft: The #FbThrift.
 * @value: The return location for the value, or #NULL.
 *
 * Reads a string value from the #FbThrift. The value returned to
 * @value should be freed with #g_free() when no longer needed. If
 * @value is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_str(FbThrift *thft, gchar **value);

/**
 * fb_thrift_read_field:
 * @thft: The #FbThrift.
 * @type: The return location for the #FbThriftType.
 * @id: The return location for the identifier, or #NULL.
 *
 * Reads a field header from the #FbThrift.
 *
 * Returns: #TRUE if the field header was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_field(FbThrift *thft, FbThriftType *type, gint16 *id);

/**
 * fb_thrift_read_stop:
 * @thft: The #FbThrift.
 *
 * Reads a field stop from the #FbThrift.
 *
 * Returns: #TRUE if the field stop was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_stop(FbThrift *thft);

/**
 * fb_thrift_read_isstop:
 * @thft: The #FbThrift.
 *
 * Determines if the next byte of the #FbThrift is a field stop.
 *
 * Returns: #TRUE if the next byte is a field stop, otherwise #FALSE.
 */
gboolean
fb_thrift_read_isstop(FbThrift *thft);

/**
 * fb_thrift_read_list:
 * @thft: The #FbThrift.
 * @type: The return location for the #FbThriftType.
 * @size: The return location for the size.
 *
 * Reads a list header from the #FbThrift.
 *
 * Returns: #TRUE if the list header was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_list(FbThrift *thft, FbThriftType *type, guint *size);

/**
 * fb_thrift_read_map:
 * @thft: The #FbThrift.
 * @ktype: The return location for the key #FbThriftType.
 * @vtype: The return location for the value #FbThriftType.
 * @size: The return location for the size.
 *
 * Reads a map header from the #FbThrift.
 *
 * Returns: #TRUE if the map header was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_map(FbThrift *thft, FbThriftType *ktype, FbThriftType *vtype,
                   guint *size);

/**
 * fb_thrift_read_set:
 * @thft: The #FbThrift.
 * @type: The return location for the #FbThriftType.
 * @size: The return location for the size.
 *
 * Reads a set header from the #FbThrift.
 *
 * Returns: #TRUE if the set header was read, otherwise #FALSE.
 */
gboolean
fb_thrift_read_set(FbThrift *thft, FbThriftType *type, guint *size);

/**
 * fb_thrift_write:
 * @thft: The #FbThrift.
 * @data: The data buffer.
 * @size: The size of @buffer.
 *
 * Writes data to the #FbThrift.
 */
void
fb_thrift_write(FbThrift *thft, gconstpointer data, guint size);

/**
 * fb_thrift_write_bool:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a boolean value to the #FbThrift.
 */
void
fb_thrift_write_bool(FbThrift *thft, gboolean value);

/**
 * fb_thrift_write_byte:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes an 8-bit integer value to the #FbThrift.
 */
void
fb_thrift_write_byte(FbThrift *thft, guint8 value);

/**
 * fb_thrift_write_dbl:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a 64-bit floating point value to the #FbThrift.
 */
void
fb_thrift_write_dbl(FbThrift *thft, gdouble value);

/**
 * fb_thrift_write_i16:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a signed 16-bit integer value to the #FbThrift. This will
 * convert the integer to the zig-zag format.
 */
void
fb_thrift_write_i16(FbThrift *thft, gint16 value);

/**
 * fb_thrift_write_vi16:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a 16-bit integer value to the #FbThrift. This writes the raw
 * integer value without converting it to the zig-zag format.
 */
void
fb_thrift_write_vi16(FbThrift *thft, guint16 value);

/**
 * fb_thrift_write_i32:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a signed 32-bit integer value to the #FbThrift. This will
 * convert the integer to the zig-zag format.
 */
void
fb_thrift_write_i32(FbThrift *thft, gint32 value);

/**
 * fb_thrift_write_vi32:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a 32-bit integer value to the #FbThrift. This writes the raw
 * integer value without converting it to the zig-zag format.
 */
void
fb_thrift_write_vi32(FbThrift *thft, guint32 value);

/**
 * fb_thrift_write_i64:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a signed 64-bit integer value to the #FbThrift. This will
 * convert the integer to the zig-zag format.
 */
void
fb_thrift_write_i64(FbThrift *thft, gint64 value);

/**
 * fb_thrift_write_vi64:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a 64-bit integer value to the #FbThrift. This writes the raw
 * integer value without converting it to the zig-zag format.
 */
void
fb_thrift_write_vi64(FbThrift *thft, guint64 value);

/**
 * fb_thrift_write_str:
 * @thft: The #FbThrift.
 * @value: The value.
 *
 * Writes a string value to the #FbThrift.
 */
void
fb_thrift_write_str(FbThrift *thft, const gchar *value);

/**
 * fb_thrift_write_field:
 * @thft: The #FbThrift.
 * @type: The #FbThriftType.
 * @id: The identifier.
 *
 * Writes a field header to the #FbThrift.
 */
void
fb_thrift_write_field(FbThrift *thft, FbThriftType type, gint16 id);

/**
 * fb_thrift_write_stop:
 * @thft: The #FbThrift.
 *
 * Writes a field stop to the #FbThrift.
 */
void
fb_thrift_write_stop(FbThrift *thft);

/**
 * fb_thrift_write_list:
 * @thft: The #FbThrift.
 * @type: The #FbThriftType.
 * @size: The size.
 *
 * Writes a list header to the #FbThrift.
 */
void
fb_thrift_write_list(FbThrift *thft, FbThriftType type, guint size);

/**
 * fb_thrift_write_map:
 * @thft: The #FbThrift.
 * @ktype: The key #FbThriftType.
 * @vtype: The value #FbThriftType.
 * @size: The size.
 *
 * Writes a map header to the #FbThrift.
 */
void
fb_thrift_write_map(FbThrift *thft, FbThriftType ktype, FbThriftType vtype,
                    guint size);

/**
 * fb_thrift_write_set:
 * @thft: The #FbThrift.
 * @type: The #FbThriftType.
 * @size: The size.
 *
 * Writes a set header to the #FbThrift.
 */
void
fb_thrift_write_set(FbThrift *thft, FbThriftType type, guint size);

/**
 * fb_thrift_t2ct:
 * @type: The #FbThriftType.
 *
 * Converts a #FbThriftType to a compact type.
 *
 * Return: The equivalent compact type.
 */
guint8
fb_thrift_t2ct(FbThriftType type);

/**
 * fb_thrift_ct2t:
 * @type: The compact type.
 *
 * Converts a compact type to an #FbThriftType.
 *
 * Return: The equivalent #FbThriftType.
 */
FbThriftType
fb_thrift_ct2t(guint8 type);

#endif /* _FACEBOOK_THRIFT_H_ */
