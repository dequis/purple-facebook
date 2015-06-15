/*
 * Copyright 2015 James Geboski <jgeboski@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _PURPLE_INTERNAL_H_
#define _PURPLE_INTERNAL_H_

#include <errno.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <locale.h>

void
_purple_socket_init(void);

void
_purple_socket_uninit(void);

#endif /* _PURPLE_INTERNAL_H_ */
