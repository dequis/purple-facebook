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

/******************************************************************************
 * g_assert_* macros
 *****************************************************************************/

#if !GLIB_CHECK_VERSION(2, 32, 0)
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
#endif

#if !GLIB_CHECK_VERSION(2, 30, 0)
#define G_VALUE_INIT {0, {{0}}}
#endif

#endif /* _GLIBCOMPAT_H_ */
