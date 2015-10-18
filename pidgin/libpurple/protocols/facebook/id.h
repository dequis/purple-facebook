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

#ifndef _FACEBOOK_ID_H_
#define _FACEBOOK_ID_H_

/**
 * SECTION:id
 * @section_id: facebook-id
 * @short_description: <filename>id.h</filename>
 * @title: Facebook Identifier
 *
 * The Facebook identifier utilities.
 */

#include <glib.h>
#include <glib/gprintf.h>

#include "util.h"

/**
 * FB_ID_FORMAT:
 *
 * The format specifier for printing and scanning an #FbId.
 */
#define FB_ID_FORMAT  G_GINT64_FORMAT

/**
 * FB_ID_MODIFIER:
 *
 * The length modifier for printing an #FbId.
 */
#define FB_ID_MODIFIER  G_GINT64_MODIFIER

/**
 * FB_ID_STRMAX:
 *
 * The maximum length, including a null-terminating character, of the
 * string representation of an #FbId.
 */
#define FB_ID_STRMAX  21

/**
 * FB_TYPE_ID:
 *
 * The #GType of an #FbId.
 */
#define FB_TYPE_ID  G_TYPE_INT64

/**
 * FB_ID_CONSTANT:
 * @v: The value.
 *
 * Inserts a literal #FbId into source code.
 *
 * Return: The literal #FbId value.
 */
#define FB_ID_CONSTANT(v)  G_GINT64_CONSTANT(v)

/**
 * FB_ID_FROM_STR:
 * @s: The string value.
 *
 * Converts a string to an #FbId.
 *
 * Return: The converted #FbId value.
 */
#define FB_ID_FROM_STR(s) g_ascii_strtoll(s, NULL, 10)

/**
 * FB_ID_IS_STR:
 * @s: The string value.
 *
 * Determines if a string is an #FbId.
 *
 * Return: #TRUE if the string is an #FbId, otherwise #FALSE.
 */
#define FB_ID_IS_STR(s) fb_util_str_is(s, G_ASCII_DIGIT)

/**
 * FB_ID_TO_STR:
 * @i: The #FbId.
 * @s: The string buffer.
 *
 * Converts an #FbId to a string. The buffer should be at least the
 * size of #FB_ID_STRMAX.
 *
 * Return: The converted string value.
 */
#define FB_ID_TO_STR(i, s) g_sprintf(s, "%" FB_ID_FORMAT, (FbId) i)

/**
 * fb_id_equal:
 *
 * Compares the values of two #FbId's for equality. See #g_int64_equal.
 */
#define fb_id_equal  g_int64_equal

/**
 * fb_id_hash:
 *
 * Converts a pointer to a #FbId hash value. See #g_int64_hash.
 */
#define fb_id_hash  g_int64_hash

/**
 * FbId:
 *
 * Represents a numeric Facebook identifier.
 */
typedef gint64 FbId;

#endif /* _FACEBOOK_ID_H_ */
