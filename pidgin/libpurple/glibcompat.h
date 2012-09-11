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

#if !GLIB_CHECK_VERSION(2, 28, 0)

static inline void g_list_free_full(GList *list, GDestroyNotify free_func)
{
	GList *it;
	it = g_list_first(list);
	while (it)
	{
		free_func(it->data);
		it = g_list_next(it);
	}
	g_list_free(list);
}

static inline void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
	GSList *it = list;
	while (it)
	{
		free_func(it->data);
		it = g_slist_next(it);
	}
	g_slist_free(list);
}

#endif /* 2.28.0 */

#endif /* _PIDGINGLIBCOMPAT_H_ */
