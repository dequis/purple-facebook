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
#ifndef _PIDGINGLIBCOMPAT_H_
#define _PIDGINGLIBCOMPAT_H_

/* This file is internal to Pidgin. Do not use!
 * Also, any public API should not depend on this file.
 */

#include <glib.h>


#ifdef __clang__

#undef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
	_Pragma ("clang diagnostic push") \
	_Pragma ("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#undef G_GNUC_END_IGNORE_DEPRECATIONS
#define G_GNUC_END_IGNORE_DEPRECATIONS \
	_Pragma ("clang diagnostic pop")

#endif /* __clang__ */


#if !GLIB_CHECK_VERSION(2, 32, 0)

#include <glib-object.h>
#include <string.h>

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#define G_GNUC_END_IGNORE_DEPRECATIONS

#define g_signal_handlers_disconnect_by_data(instance, data) \
	g_signal_handlers_disconnect_matched((instance), G_SIGNAL_MATCH_DATA, \
			0, 0, NULL, NULL, (data))

static inline GThread * g_thread_try_new(const gchar *name, GThreadFunc func,
	gpointer data, GError **error)
{
	return g_thread_create(func, data, TRUE, error);
}

#if !GLIB_CHECK_VERSION(2, 30, 0)

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

#if !GLIB_CHECK_VERSION(2, 28, 0)

static inline gint64 g_get_monotonic_time(void)
{
	GTimeVal time_s;

	g_get_current_time(&time_s);

	return ((gint64)time_s.tv_sec << 32) | time_s.tv_usec;
}

static inline void g_list_free_full(GList *list, GDestroyNotify free_func)
{
	g_list_foreach(list, (GFunc)free_func, NULL);
	g_list_free(list);
}

static inline void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
	g_slist_foreach(list, (GFunc)free_func, NULL);
	g_slist_free(list);
}

#if !GLIB_CHECK_VERSION(2, 26, 0)

typedef struct stat GStatBuf;

static inline void g_object_notify_by_pspec(GObject *object, GParamSpec *pspec)
{
	g_object_notify(object, g_param_spec_get_name(pspec));
}

static inline void g_object_class_install_properties(GObjectClass *oclass,
	guint n_pspecs, GParamSpec **pspecs)
{
	guint i;
	for (i = 1; i < n_pspecs; ++i)
		g_object_class_install_property(oclass, i, pspecs[i]);
}

#endif /* < 2.26.0 */

#endif /* < 2.28.0 */

#endif /* < 2.30.0 */

#endif /* < 2.32.0 */

#endif /* _PIDGINGLIBCOMPAT_H_ */
