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

/**
 * SECTION:util
 * @section_id: facebook-util
 * @short_description: <filename>util.h</filename>
 * @title: General Utilities
 *
 * The general utilities.
 */

#include <glib.h>

#include <libpurple/util.h>

#include "account.h"
#include "conversationtypes.h"
#include "debug.h"
#include "connection.h"
#include "conversation.h"

/**
 * FB_UTIL_DEBUG_INFO:
 *
 * Shortcut #PurpleDebugLevel for unsafe and verbose info messages.
 */
#define FB_UTIL_DEBUG_INFO ( \
		PURPLE_DEBUG_INFO | \
		FB_UTIL_DEBUG_FLAG_UNSAFE | \
		FB_UTIL_DEBUG_FLAG_VERBOSE \
	)

/**
 * FB_UTIL_ERROR:
 *
 * The #GQuark of the domain of utility errors.
 */
#define FB_UTIL_ERROR fb_util_error_quark()

/**
 * FbUtilRequestBuddyFunc:
 * @buddies: The list of #PurpleBuddy's.
 * @data: The user-defined data.
 */
typedef void (*FbUtilRequestBuddyFunc) (GSList *buddies, gpointer data);

/**
 * FbUtilDebugFlags:
 * @FB_UTIL_DEBUG_FLAG_UNSAFE: The message is unsafe.
 * @FB_UTIL_DEBUG_FLAG_VERBOSE: The message is verbose.
 * @FB_UTIL_DEBUG_FLAG_ALL: All of the flags.
 *
 * The debugging message flags. These flags are inserted on top of
 * a #PurpleDebugLevel.
 */
typedef enum
{
	FB_UTIL_DEBUG_FLAG_UNSAFE  = 1 << 25,
	FB_UTIL_DEBUG_FLAG_VERBOSE = 1 << 26,
	FB_UTIL_DEBUG_FLAG_ALL     = 3 << 25
} FbUtilDebugFlags;

/**
 * FbUtilError:
 * @FB_UTIL_ERROR_GENERAL: General failure.
 *
 * The error codes for the #FB_UTIL_ERROR domain.
 */
typedef enum
{
	FB_UTIL_ERROR_GENERAL
} FbUtilError;

/**
 * fb_util_error_quark:
 *
 * Gets the #GQuark of the domain of utility errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_util_error_quark(void);

/**
 * fb_util_account_find_buddy:
 * @acct: The #PurpleAccount.
 * @chat: The #PurpleChatConversation.
 * @name: The name of the buddy.
 * @error: The return location for the #GError, or #NULL.
 *
 * Finds a buddy by their name or alias.
 *
 * Returns: The #PurpleBuddy if found, otherwise #NULL.
 */
PurpleBuddy *
fb_util_account_find_buddy(PurpleAccount *acct, PurpleChatConversation *chat,
                           const gchar *name, GError **error);

/**
 * fb_util_debug:
 * @level: The #PurpleDebugLevel.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message. If the messages is unsafe or verbose,
 * apply the appropriate #FbUtilDebugFlags.
 */
void
fb_util_debug(PurpleDebugLevel level, const gchar *format, ...)
              G_GNUC_PRINTF(2, 3);

/**
 * fb_util_vdebug:
 * @level: The #PurpleDebugLevel.
 * @format: The format string literal.
 * @ap: The #va_list.
 *
 * Logs a debugging message. If the messages is unsafe or verbose,
 * apply the appropriate #FbUtilDebugFlags.
 */
void
fb_util_vdebug(PurpleDebugLevel level, const gchar *format, va_list ap);

/**
 * fb_util_debug_misc:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of #PURPLE_DEBUG_MISC.
 */
void
fb_util_debug_misc(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_info:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of #PURPLE_DEBUG_INFO.
 */
void
fb_util_debug_info(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_warning:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of #PURPLE_DEBUG_WARNING.
 */
void
fb_util_debug_warning(const gchar *format, ...)
                      G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_error:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of #PURPLE_DEBUG_ERROR.
 */
void
fb_util_debug_error(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_fatal:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of #PURPLE_DEBUG_FATAL.
 */
void
fb_util_debug_fatal(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_hexdump:
 * @level: The #PurpleDebugLevel.
 * @bytes: The #GByteArray.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a hexdump of a #GByteArray. If the messages is unsafe or
 * verbose, apply the appropriate #FbUtilDebugFlags.
 */
void
fb_util_debug_hexdump(PurpleDebugLevel level, const GByteArray *bytes,
                      const gchar *format, ...)
                      G_GNUC_PRINTF(3, 4);

/**
 * fb_util_locale_str:
 *
 * Gets the locale string (ex: en_US) from the system. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The locale string.
 */
gchar *
fb_util_locale_str(void);

/**
 * fb_util_randstr:
 * @size: The size of the string.
 *
 * Gets a random alphanumeric string. The returned string should be
 * freed with #g_free() when no longer needed.
 *
 * Returns: The random string.
 */
gchar *
fb_util_randstr(gsize size);

/**
 * fb_util_request_buddy:
 * @gc: The #PurpleConnection.
 * @title: The title of the message or #NULL.
 * @primary: The main point of the message or #NULL.
 * @secondary: The secondary information or #NULL.
 * @select: A #GSList of selected buddies, or #NULL.
 * @multi: #TRUE to for multiple buddy selections, otherwise #FALSE.
 * @ok_cb: The callback for the `OK` button or #NULL.
 * @cancel_cb: The callback for the `Cancel` button or #NULL.
 * @data: The user-defined data.
 *
 * Displays a buddy list selection form.
 *
 * Returns: The UI-specific handle.
 */
gpointer
fb_util_request_buddy(PurpleConnection *gc, const gchar *title,
                      const gchar *primary, const gchar *secondary,
                      GSList *select, gboolean multi, GCallback ok_cb,
                      GCallback cancel_cb, gpointer data);

/**
 * fb_util_serv_got_im:
 * @gc: The #PurpleConnection.
 * @who: The message sender or receiver.
 * @text: The message text.
 * @flags: The #PurpleMessageFlags.
 * @timestamp: The message timestamp.
 *
 * Handles an incoming IM message. This function is special in that it
 * handles self messages. This function determines the direction of the
 * message from the #PurpleMessageFlags.
 */
void
fb_util_serv_got_im(PurpleConnection *gc, const gchar *who, const gchar *text,
                    PurpleMessageFlags flags, guint64 timestamp);

/**
 * fb_util_serv_got_chat_in:
 * @gc: The #PurpleConnection.
 * @id: The id of the chat.
 * @who: The message sender or receiver.
 * @text: The message text.
 * @flags: The #PurpleMessageFlags.
 * @timestamp: The message timestamp.
 *
 * Handles an incoming chat message. This function is special in that
 * it handles self messages. This function determines the direction of
 * the message from the #PurpleMessageFlags.
 */
void
fb_util_serv_got_chat_in(PurpleConnection *gc, gint id, const gchar *who,
                         const gchar *text, PurpleMessageFlags flags,
                         guint64 timestamp);

/**
 * fb_util_str_is:
 * @str: The string.
 * @type: The #GAsciiType.
 *
 * Determines if @str abides to the #GAsciiType.
 *
 * Returns: #TRUE if the string abides to @type, otherwise #FALSE.
 */
gboolean
fb_util_str_is(const gchar *str, GAsciiType type);

/**
 * fb_util_zcompressed:
 * @bytes: The #GByteArray.
 *
 * Determines if the #GByteArray is zlib compressed.
 *
 * Returns: #TRUE if the #GByteArray is compressed, otherwise #FALSE.
 */
gboolean
fb_util_zcompressed(const GByteArray *bytes);

/**
 * fb_util_zcompress:
 * @bytes: The #GByteArray.
 *
 * Compresses a #GByteArray with zlib. The returned #GByteArray should
 * be freed with #g_byte_array_free() when no longer needed.
 *
 * Returns: The compressed #GByteArray.
 */
GByteArray *
fb_util_zcompress(const GByteArray *bytes);

/**
 * fb_util_zuncompress:
 * @bytes: The #GByteArray.
 *
 * Uncompresses a #GByteArray with zlib. The returned #GByteArray
 * should be freed with #g_byte_array_free() when no longer needed.
 *
 * Returns: The uncompressed #GByteArray, or #NULL on error.
 */
GByteArray *
fb_util_zuncompress(const GByteArray *bytes);

#endif /* _FACEBOOK_UTIL_H_ */
