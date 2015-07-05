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

#include "connection.h"
#include "glibcompat.h"

#define FB_UTIL_DEBUG_INFO (        \
		PURPLE_DEBUG_INFO |         \
		FB_UTIL_DEBUG_FLAG_UNSAFE | \
		FB_UTIL_DEBUG_FLAG_VERBOSE  \
	)

#define FB_UTIL_ERROR fb_util_error_quark()

typedef enum _FbUtilDebugFlags FbUtilDebugFlags;
typedef enum _FbUtilError FbUtilError;

typedef void (*FbUtilRequestBuddyFunc) (GSList *buddies, gpointer data);

enum _FbUtilDebugFlags
{
	FB_UTIL_DEBUG_FLAG_UNSAFE  = 1 << 25,
	FB_UTIL_DEBUG_FLAG_VERBOSE = 1 << 26
};

enum _FbUtilError
{
	FB_UTIL_ERROR_GENERAL
};


GQuark
fb_util_error_quark(void);

PurpleBuddy *
fb_util_account_find_buddy(PurpleAccount *acct, PurpleChatConversation *chat,
                           const gchar *name, GError **error);

void
fb_util_debug(PurpleDebugLevel level, const gchar *format, ...)
              G_GNUC_PRINTF(2, 3);

void
fb_util_vdebug(PurpleDebugLevel level, const gchar *format, va_list ap);

void
fb_util_debug_misc(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

void
fb_util_debug_info(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

void
fb_util_debug_warning(const gchar *format, ...)
                      G_GNUC_PRINTF(1, 2);

void
fb_util_debug_error(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

void
fb_util_debug_fatal(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

void
fb_util_debug_hexdump(PurpleDebugLevel level, const GByteArray *bytes,
                      const gchar *format, ...)
                      G_GNUC_PRINTF(3, 4);

gchar *
fb_util_locale_str(void);

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
