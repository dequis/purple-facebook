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

#ifndef _FACEBOOK_GLIBCOMPAT_H_
#define _FACEBOOK_GLIBCOMPAT_H_

#include <glib.h>
#include <glib-object.h>
#include <libpurple/glibcompat.h>

#if !GLIB_CHECK_VERSION(2, 34, 0)

static inline GSList *
g_slist_copy_deep(GSList *list, GCopyFunc func, gpointer data)
{
	GSList *ret = NULL;
	GSList *l;
	gpointer *ptr;

	if (G_UNLIKELY(func == NULL)) {
		return g_slist_copy(list);
	}

	for (l = list; l != NULL; l = l->next) {
		ret = g_slist_prepend(ret, func(l->data, data));
	}

	return g_slist_reverse(ret);
}

#if !GLIB_CHECK_VERSION(2, 32, 0)

static inline GByteArray*
g_byte_array_new_take(guint8 *data, gsize len)
{
	GByteArray *array;

	array = g_byte_array_new();
	g_byte_array_append(array, data, len);
	g_free(data);

	return array;
}

#if !GLIB_CHECK_VERSION(2, 30, 0)

#define G_VALUE_INIT  {0, {{0}}}

#endif /* < 2.30.0 */

#endif /* < 2.32.0 */

#endif /* < 2.34.0 */

#endif /* _FACEBOOK_GLIBCOMPAT_H_ */
