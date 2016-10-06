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

#include <gio/gio.h>
#include <stdarg.h>
#include <string.h>

#include "buddylist.h"
#include "conversations.h"
#include "glibcompat.h"
#include "message.h"
#include "request.h"
#include "server.h"

#include "util.h"

GQuark
fb_util_error_quark(void)
{
	static GQuark q = 0;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-util-error-quark");
	}

	return q;
}

PurpleBuddy *
fb_util_account_find_buddy(PurpleAccount *acct, PurpleChatConversation *chat,
                           const gchar *search, GError **error)
{
	const gchar *alias;
	const gchar *name;
	GSList *buddies;
	GSList *l;
	guint retc;
	PurpleBuddy *ret = NULL;

	g_return_val_if_fail(PURPLE_IS_ACCOUNT(acct), NULL);
	g_return_val_if_fail(search != NULL, NULL);

	buddies = purple_blist_find_buddies(acct, NULL);

	for (retc = 0, l = buddies; l != NULL; l = l->next) {
		name = purple_buddy_get_name(l->data);
		alias = purple_buddy_get_alias(l->data);

		if ((chat != NULL) &&
		    !purple_chat_conversation_has_user(chat, name))
		{
			continue;
		}

		if (g_ascii_strcasecmp(name, search) == 0) {
			ret = l->data;
			retc++;
		}

		if (g_ascii_strcasecmp(alias, search) == 0) {
			ret = l->data;
			retc++;
		}
	}

	if (retc == 0) {
		g_set_error(error, FB_UTIL_ERROR, FB_UTIL_ERROR_GENERAL,
		            _("Buddy %s not found"), search);
	} else if (retc > 1) {
		g_set_error(error, FB_UTIL_ERROR, FB_UTIL_ERROR_GENERAL,
		            _("Buddy name %s is ambiguous"), search);
		ret = NULL;
	}

	g_slist_free(buddies);
	return ret;
}

void
fb_util_debug(PurpleDebugLevel level, const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(level, format, ap);
	va_end(ap);
}

void
fb_util_vdebug(PurpleDebugLevel level, const gchar *format, va_list ap)
{
	gboolean unsafe;
	gboolean verbose;
	gchar *str;

	g_return_if_fail(format != NULL);

	unsafe = (level & FB_UTIL_DEBUG_FLAG_UNSAFE) != 0;
	verbose = (level & FB_UTIL_DEBUG_FLAG_VERBOSE) != 0;

	if ((unsafe && !purple_debug_is_unsafe()) ||
	    (verbose && !purple_debug_is_verbose()))
	{
		return;
	}

	/* Ensure all local flags are removed */
	level &= ~FB_UTIL_DEBUG_FLAG_ALL;

	str = g_strdup_vprintf(format, ap);
	purple_debug(level, "facebook", "%s\n", str);
	g_free(str);
}

void
fb_util_debug_misc(const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(PURPLE_DEBUG_MISC, format, ap);
	va_end(ap);
}

void
fb_util_debug_info(const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(PURPLE_DEBUG_INFO, format, ap);
	va_end(ap);
}

void
fb_util_debug_warning(const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(PURPLE_DEBUG_WARNING, format, ap);
	va_end(ap);
}

void
fb_util_debug_error(const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(PURPLE_DEBUG_ERROR, format, ap);
	va_end(ap);
}

void
fb_util_debug_fatal(const gchar *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fb_util_vdebug(PURPLE_DEBUG_FATAL, format, ap);
	va_end(ap);
}

void
fb_util_debug_hexdump(PurpleDebugLevel level, const GByteArray *bytes,
                      const gchar *format, ...)
{
	gchar c;
	guint i;
	guint j;
	GString *gstr;
	va_list ap;

	static const gchar *indent = "  ";

	g_return_if_fail(bytes != NULL);

	if (format != NULL) {
		va_start(ap, format);
		fb_util_vdebug(level, format, ap);
		va_end(ap);
	}

	gstr = g_string_sized_new(80);

	for (i = 0; i < bytes->len; i += 16) {
		g_string_append_printf(gstr, "%s%08x  ", indent, i);

		for (j = 0; j < 16; j++) {
			if ((i + j) < bytes->len) {
				g_string_append_printf(gstr, "%02x ",
				                       bytes->data[i + j]);
			} else {
				g_string_append(gstr, "   ");
			}

			if (j == 7) {
				g_string_append_c(gstr, ' ');
			}
		}

		g_string_append(gstr, " |");

		for (j = 0; (j < 16) && ((i + j) < bytes->len); j++) {
			c = bytes->data[i + j];

			if (!g_ascii_isprint(c) || g_ascii_isspace(c)) {
				c = '.';
			}

			g_string_append_c(gstr, c);
		}

		g_string_append_c(gstr, '|');
		fb_util_debug(level, "%s", gstr->str);
		g_string_erase(gstr, 0, -1);
	}

	g_string_append_printf(gstr, "%s%08x", indent, i);
	fb_util_debug(level, "%s", gstr->str);
	g_string_free(gstr, TRUE);
}

gchar *
fb_util_get_locale(void)
{
	const gchar * const *langs;
	const gchar *lang;
	gchar *chr;
	guint i;

	static const gchar chrs[] = {'.', '@'};

	langs = g_get_language_names();
	lang = langs[0];

	if (purple_strequal(lang, "C")) {
		return g_strdup("en_US");
	}

	for (i = 0; i < G_N_ELEMENTS(chrs); i++) {
		chr = strchr(lang, chrs[i]);

		if (chr != NULL) {
			return g_strndup(lang, chr - lang);
		}
	}

	return g_strdup(lang);
}

gchar *
fb_util_rand_alnum(guint len)
{
	gchar *ret;
	GRand *rand;
	guint i;
	guint j;

	static const gchar chars[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789";
	static const gsize charc = G_N_ELEMENTS(chars) - 1;

	g_return_val_if_fail(len > 0, NULL);
	rand = g_rand_new();
	ret = g_new(gchar, len + 1);

	for (i = 0; i < len; i++) {
		j = g_rand_int_range(rand, 0, charc);
		ret[i] = chars[j];
	}

	ret[len] = 0;
	g_rand_free(rand);
	return ret;
}

static void
fb_util_request_buddy_ok(gpointer *mata, PurpleRequestFields *fields)
{
	FbUtilRequestBuddyFunc func = mata[0];
	GList *l;
	GList *select;
	gpointer data = mata[2];
	GSList *ret = NULL;
	PurpleBuddy *bdy;
	PurpleRequestField *field;

	if (func == NULL) {
		g_free(mata);
		return;
	}

	field = purple_request_fields_get_field(fields, "buddy");
	select = purple_request_field_list_get_selected(field);

	for (l = select; l != NULL; l = l->next) {
		bdy = purple_request_field_list_get_data(field, l->data);
		ret = g_slist_prepend(ret, bdy);
	}

	ret = g_slist_reverse(ret);
	func(ret, data);

	g_slist_free(ret);
	g_free(mata);
}

static void
fb_util_request_buddy_cancel(gpointer *mata, PurpleRequestFields *fields)
{
	FbUtilRequestBuddyFunc func = mata[1];
	gpointer data = mata[2];

	if (func != NULL) {
		func(NULL, data);
	}

	g_free(mata);
}

gpointer
fb_util_request_buddy(PurpleConnection *gc, const gchar *title,
                      const gchar *primary, const gchar *secondary,
                      GSList *select, gboolean multi, GCallback ok_cb,
		      GCallback cancel_cb, gpointer data)
{
	const gchar *alias;
	const gchar *name;
	gchar *str;
	GList *items = NULL;
	gpointer *mata;
	GSList *buddies;
	GSList *l;
	PurpleAccount *acct;
	PurpleRequestCommonParameters *cpar;
	PurpleRequestField *field;
	PurpleRequestFieldGroup *group;
	PurpleRequestFields *fields;

	mata = g_new0(gpointer, 3);
	mata[0] = ok_cb;
	mata[1] = cancel_cb;
	mata[2] = data;

	acct = purple_connection_get_account(gc);
	buddies = purple_blist_find_buddies(acct, NULL);
	buddies = g_slist_sort(buddies, (GCompareFunc) g_ascii_strcasecmp);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_list_new("buddy", NULL);
	purple_request_field_list_set_multi_select(field, multi);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	for (l = buddies; l != NULL; l = l->next) {
		name = purple_buddy_get_name(l->data);
		alias = purple_buddy_get_alias(l->data);
		str = g_strdup_printf("%s (%s)", alias, name);
		purple_request_field_list_add_icon(field, str, NULL, l->data);
		g_free(str);
	}

	for (l = select; l != NULL; l = l->next) {
		name = purple_buddy_get_name(l->data);
		alias = purple_buddy_get_alias(l->data);
		str = g_strdup_printf("%s (%s)", alias, name);
		items = g_list_append(items, str);
	}

	purple_request_field_list_set_selected(field, items);
	g_slist_free(buddies);
	g_list_free_full(items, g_free);

	cpar = purple_request_cpar_from_connection(gc);
	return purple_request_fields(gc, title, primary, secondary, fields,
	                             _("Ok"),
	                             G_CALLBACK(fb_util_request_buddy_ok),
				     _("Cancel"),
	                             G_CALLBACK(fb_util_request_buddy_cancel),
				     cpar, mata);
}

void
fb_util_serv_got_im(PurpleConnection *gc, const gchar *who, const gchar *text,
                    PurpleMessageFlags flags, guint64 timestamp)
{
	const gchar *name;
	PurpleAccount *acct;
	PurpleIMConversation *conv;
	PurpleMessage *msg;

	if (!(flags & PURPLE_MESSAGE_SEND)) {
		purple_serv_got_im(gc, who, text, flags, timestamp);
		return;
	}

	acct = purple_connection_get_account(gc);
	conv = purple_conversations_find_im_with_account(who, acct);

	if (conv == NULL) {
		conv = purple_im_conversation_new(acct, who);
	}

	name = purple_account_get_username(acct);
	msg = purple_message_new_outgoing(name, text, flags);
	purple_message_set_time(msg, timestamp);
	purple_conversation_write_message(PURPLE_CONVERSATION(conv), msg);
}

void
fb_util_serv_got_chat_in(PurpleConnection *gc, gint id, const gchar *who,
                         const gchar *text, PurpleMessageFlags flags,
			 guint64 timestamp)
{
	const gchar *name;
	PurpleAccount *acct;
	PurpleChatConversation *conv;
	PurpleMessage *msg;

	if (!(flags & PURPLE_MESSAGE_SEND)) {
		purple_serv_got_chat_in(gc, id, who, flags, text, timestamp);
		return;
	}

	acct = purple_connection_get_account(gc);
	conv = purple_conversations_find_chat(gc, id);

	name = purple_account_get_username(acct);
	msg = purple_message_new_outgoing(name, text, flags);
	purple_message_set_time(msg, timestamp);
	purple_conversation_write_message(PURPLE_CONVERSATION(conv), msg);
}

gboolean
fb_util_strtest(const gchar *str, GAsciiType type)
{
	gsize i;
	gsize size;
	guchar c;

	g_return_val_if_fail(str != NULL, FALSE);
	size = strlen(str);

	for (i = 0; i < size; i++) {
		c = (guchar) str[i];

		if ((g_ascii_table[c] & type) == 0) {
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
fb_util_zlib_test(const GByteArray *bytes)
{
	guint8 b0;
	guint8 b1;

	g_return_val_if_fail(bytes != NULL, FALSE);

	if (bytes->len < 2) {
		return FALSE;
	}

	b0 = *(bytes->data + 0);
	b1 = *(bytes->data + 1);

	return ((((b0 << 8) | b1) % 31) == 0) &&    /* Check the header */
	       ((b0 & 0x0F) == 8 /* Z_DEFLATED */); /* Check the method */
}

static GByteArray *
fb_util_zlib_conv(GConverter *conv, const GByteArray *bytes, GError **error)
{
	GByteArray *ret;
	GConverterResult res;
	gsize cize = 0;
	gsize rize;
	gsize wize;
	guint8 data[1024];

	ret = g_byte_array_new();

	while (TRUE) {
		rize = 0;
		wize = 0;

		res = g_converter_convert(conv,
		                          bytes->data + cize,
		                          bytes->len - cize,
		                          data, sizeof data,
		                          G_CONVERTER_INPUT_AT_END,
		                          &rize, &wize, error);

		switch (res) {
		case G_CONVERTER_CONVERTED:
			g_byte_array_append(ret, data, wize);
			cize += rize;
			break;

		case G_CONVERTER_ERROR:
			g_byte_array_free(ret, TRUE);
			return NULL;

		case G_CONVERTER_FINISHED:
			g_byte_array_append(ret, data, wize);
			return ret;

		default:
			break;
		}
	}
}

GByteArray *
fb_util_zlib_deflate(const GByteArray *bytes, GError **error)
{
	GByteArray *ret;
	GZlibCompressor *conv;

	conv = g_zlib_compressor_new(G_ZLIB_COMPRESSOR_FORMAT_ZLIB, -1);
	ret = fb_util_zlib_conv(G_CONVERTER(conv), bytes, error);
	g_object_unref(conv);
	return ret;
}

GByteArray *
fb_util_zlib_inflate(const GByteArray *bytes, GError **error)
{
	GByteArray *ret;
	GZlibDecompressor *conv;

	conv = g_zlib_decompressor_new(G_ZLIB_COMPRESSOR_FORMAT_ZLIB);
	ret = fb_util_zlib_conv(G_CONVERTER(conv), bytes, error);
	g_object_unref(conv);
	return ret;
}
