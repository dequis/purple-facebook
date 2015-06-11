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

#include <glib.h>
#include <glib/gprintf.h>

#include "util.h"

#define FB_ID_CONSTANT(v)  G_GINT64_CONSTANT(v)
#define FB_ID_FORMAT       G_GINT64_FORMAT
#define FB_ID_MODIFIER     G_GINT64_MODIFIER
#define FB_ID_STRMAX       21
#define FB_TYPE_ID         G_TYPE_INT64
#define fb_id_hash         g_int64_hash
#define fb_id_equal        g_int64_equal

#define FB_ID_FROM_STR(s) \
	g_ascii_strtoll(s, NULL, 10)

#define FB_ID_IS_STR(s) \
	fb_util_str_is(s, G_ASCII_DIGIT)

#define FB_ID_TO_STR(i, s) \
	g_sprintf(s, "%" FB_ID_FORMAT, (FbId) i)

typedef gint64 FbId;

#endif /* _FACEBOOK_ID_H_ */
