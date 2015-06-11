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

#ifndef _FACEBOOK_UTIL_H_
#define _FACEBOOK_UTIL_H_

#include <glib.h>

#include "connection.h"

typedef void (*FbUtilRequestBuddyFunc) (GSList *buddies, gpointer data);

gchar *
fb_util_randstr(gsize size);

gpointer
fb_util_request_buddy(PurpleConnection *gc, const gchar *title,
                      const gchar *primary, const gchar *secondary,
                      GSList *select, gboolean multi, GCallback ok_cb,
                      GCallback cancel_cb, gpointer data);

gboolean
fb_util_str_is(const gchar *str, GAsciiType type);

gboolean
fb_util_zcompressed(const GByteArray *bytes);

GByteArray *
fb_util_zcompress(const GByteArray *bytes);

GByteArray *
fb_util_zuncompress(const GByteArray *bytes);

#endif /* _FACEBOOK_UTIL_H_ */
