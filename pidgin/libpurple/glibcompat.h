/* pidgin
 *
 * Pidgin is the legal property of its developers, whose names are too numerous
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301 USA
 */

#ifndef _GLIBCOMPAT_H_
#define _GLIBCOMPAT_H_
/*
 * SECTION:glibcompat
 * @section_id: libpurple-glibcompat
 * @short_description: <filename>glibcompat.h</filename>
 * @title: GLib version-dependent definitions
 *
 * This file is internal to libpurple. Do not use!
 * Also, any public API should not depend on this file.
 */

#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 36, 0)

#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

static inline gboolean g_close(gint fd, GError **error)
{
	int res;
	int errsv;

	res = close(fd);

	if (G_LIKELY(res == 0))
		return TRUE;
	if (G_UNLIKELY(errno == EINTR))
		return TRUE;

	errsv = errno;
	g_set_error_literal(error, G_FILE_ERROR,
		g_file_error_from_errno(errsv), g_strerror(errsv));
	errno = errsv;

	return FALSE;
}

#if !GLIB_CHECK_VERSION(2, 32, 0)

#include <glib-object.h>
#include <string.h>

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#define G_GNUC_END_IGNORE_DEPRECATIONS

#define G_SOURCE_REMOVE FALSE
#define G_SOURCE_CONTINUE TRUE

#define g_signal_handlers_disconnect_by_data(instance, data) \
	g_signal_handlers_disconnect_matched((instance), G_SIGNAL_MATCH_DATA, \
			0, 0, NULL, NULL, (data))

static inline GByteArray * g_byte_array_new_take(guint8 *data, gsize len)
{
	GByteArray *array;

	array = g_byte_array_new();
	g_byte_array_append(array, data, len);
	g_free(data);

	return array;
}

static inline void g_queue_free_full(GQueue *queue, GDestroyNotify free_func)
{
	g_queue_foreach(queue, (GFunc)free_func, NULL);
	g_queue_free(queue);
}

static inline GThread * g_thread_try_new(const gchar *name, GThreadFunc func,
	gpointer data, GError **error)
{
	return g_thread_create(func, data, TRUE, error);
}

#if !GLIB_CHECK_VERSION(2, 30, 0)

#define G_VALUE_INIT {0, {{0}}}

static inline gchar *g_utf8_substring(const gchar *str, glong start_pos,
	glong end_pos)
{
	gchar *start = g_utf8_offset_to_pointer(str, start_pos);
	gchar *end = g_utf8_offset_to_pointer(start, end_pos - start_pos);
	gchar *out = g_malloc(end - start + 1);

	memcpy(out, start, end - start);
	out[end - start] = 0;

	return out;
}

#endif /* < 2.30.0 */

#endif /* < 2.32.0 */

#endif /* < 2.36.0 */


/* glib's definition of g_stat+GStatBuf seems to be broken on mingw64-w32 (and
 * possibly other 32-bit windows), so instead of relying on it,
 * we'll define our own.
 */
#if defined(_WIN32) && !defined(_MSC_VER) && !defined(_WIN64)
#  include <glib/gstdio.h>
typedef struct _stat GStatBufW32;
static inline int
purple_g_stat(const gchar *filename, GStatBufW32 *buf)
{
	return g_stat(filename, (GStatBuf*)buf);
}
#  define GStatBuf GStatBufW32
#  define g_stat purple_g_stat
#endif


#ifdef __clang__

#undef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
	_Pragma ("clang diagnostic push") \
	_Pragma ("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#undef G_GNUC_END_IGNORE_DEPRECATIONS
#define G_GNUC_END_IGNORE_DEPRECATIONS \
	_Pragma ("clang diagnostic pop")

#endif /* __clang__ */

#endif /* _GLIBCOMPAT_H_ */
