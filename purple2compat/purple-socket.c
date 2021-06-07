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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301 USA
 */

#include "purple-socket.h"

#include "internal.h"

#include "debug.h"
#include "proxy.h"
#include "sslconn.h"

typedef enum {
	PURPLE_SOCKET_STATE_DISCONNECTED = 0,
	PURPLE_SOCKET_STATE_CONNECTING,
	PURPLE_SOCKET_STATE_CONNECTED,
	PURPLE_SOCKET_STATE_ERROR
} PurpleSocketState;

struct _PurpleSocket
{
	PurpleConnection *gc;
	gchar *host;
	int port;
	gboolean is_tls;
	GHashTable *data;

	PurpleSocketState state;

	PurpleSslConnection *tls_connection;
	PurpleProxyConnectData *raw_connection;
	int fd;
	guint inpa;

	PurpleSocketConnectCb cb;
	gpointer cb_data;
};

static GHashTable *handles = NULL;

static void
handle_add(PurpleSocket *ps)
{
	PurpleConnection *gc = ps->gc;
	GSList *l;

	l = g_hash_table_lookup(handles, gc);
	l = g_slist_prepend(l, ps);
	g_hash_table_insert(handles, gc, l);
}

static void
handle_remove(PurpleSocket *ps)
{
	PurpleConnection *gc = ps->gc;
	GSList *l;

	l = g_hash_table_lookup(handles, gc);
	l = g_slist_remove(l, ps);
	g_hash_table_insert(handles, gc, l);
}

void
_purple_socket_init(void)
{
	handles = g_hash_table_new(g_direct_hash, g_direct_equal);
}

void
_purple_socket_uninit(void)
{
	g_hash_table_destroy(handles);
	handles = NULL;
}

PurpleSocket *
purple_socket_new(PurpleConnection *gc)
{
	PurpleSocket *ps = g_new0(PurpleSocket, 1);

	ps->gc = gc;
	ps->fd = -1;
	ps->port = -1;
	ps->data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	handle_add(ps);

	return ps;
}

PurpleConnection *
purple_socket_get_connection(PurpleSocket *ps)
{
	g_return_val_if_fail(ps != NULL, NULL);

	return ps->gc;
}

static gboolean
purple_socket_check_state(PurpleSocket *ps, PurpleSocketState wanted_state)
{
	g_return_val_if_fail(ps != NULL, FALSE);

	if (ps->state == wanted_state)
		return TRUE;

	purple_debug_error("socket", "invalid state: %d (should be: %d)",
		ps->state, wanted_state);
	ps->state = PURPLE_SOCKET_STATE_ERROR;
	return FALSE;
}

void
purple_socket_set_tls(PurpleSocket *ps, gboolean is_tls)
{
	g_return_if_fail(ps != NULL);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_DISCONNECTED))
		return;

	ps->is_tls = is_tls;
}

void
purple_socket_set_host(PurpleSocket *ps, const gchar *host)
{
	g_return_if_fail(ps != NULL);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_DISCONNECTED))
		return;

	g_free(ps->host);
	ps->host = g_strdup(host);
}

void
purple_socket_set_port(PurpleSocket *ps, int port)
{
	g_return_if_fail(ps != NULL);
	g_return_if_fail(port >= 0);
	g_return_if_fail(port <= 65535);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_DISCONNECTED))
		return;

	ps->port = port;
}

static void
_purple_socket_connected_raw(gpointer _ps, gint fd, const gchar *error_message)
{
	PurpleSocket *ps = _ps;

	ps->raw_connection = NULL;

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTING)) {
		if (fd > 0)
			close(fd);
		ps->cb(ps, _("Invalid socket state"), ps->cb_data);
		return;
	}

	if (fd <= 0 || error_message != NULL) {
		if (error_message == NULL)
			error_message = _("Unknown error");
		ps->fd = -1;
		ps->state = PURPLE_SOCKET_STATE_ERROR;
		ps->cb(ps, error_message, ps->cb_data);
		return;
	}

	ps->state = PURPLE_SOCKET_STATE_CONNECTED;
	ps->fd = fd;
	ps->cb(ps, NULL, ps->cb_data);
}

static void
_purple_socket_connected_tls(gpointer _ps, PurpleSslConnection *tls_connection,
	PurpleInputCondition cond)
{
	PurpleSocket *ps = _ps;

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTING)) {
		purple_ssl_close(tls_connection);
		ps->tls_connection = NULL;
		ps->cb(ps, _("Invalid socket state"), ps->cb_data);
		return;
	}

	if (ps->tls_connection->fd <= 0) {
		ps->state = PURPLE_SOCKET_STATE_ERROR;
		purple_ssl_close(tls_connection);
		ps->tls_connection = NULL;
		ps->cb(ps, _("Invalid file descriptor"), ps->cb_data);
		return;
	}

	ps->state = PURPLE_SOCKET_STATE_CONNECTED;
	ps->fd = ps->tls_connection->fd;
	ps->cb(ps, NULL, ps->cb_data);
}

static void
_purple_socket_connected_tls_error(PurpleSslConnection *ssl_connection,
	PurpleSslErrorType error, gpointer _ps)
{
	PurpleSocket *ps = _ps;

	ps->state = PURPLE_SOCKET_STATE_ERROR;
	ps->tls_connection = NULL;
	ps->cb(ps, purple_ssl_strerror(error), ps->cb_data);
}

gboolean
purple_socket_connect(PurpleSocket *ps, PurpleSocketConnectCb cb,
	gpointer user_data)
{
	PurpleAccount *account = NULL;

	g_return_val_if_fail(ps != NULL, FALSE);

	if (ps->gc && purple_connection_is_disconnecting(ps->gc)) {
		purple_debug_error("socket", "connection is being destroyed");
		ps->state = PURPLE_SOCKET_STATE_ERROR;
		return FALSE;
	}

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_DISCONNECTED))
		return FALSE;
	ps->state = PURPLE_SOCKET_STATE_CONNECTING;

	if (ps->host == NULL || ps->port < 0) {
		purple_debug_error("socket", "Host or port is not specified");
		ps->state = PURPLE_SOCKET_STATE_ERROR;
		return FALSE;
	}

	if (ps->gc != NULL)
		account = purple_connection_get_account(ps->gc);

	ps->cb = cb;
	ps->cb_data = user_data;

	if (ps->is_tls) {
		ps->tls_connection = purple_ssl_connect(account, ps->host,
			ps->port, _purple_socket_connected_tls,
			_purple_socket_connected_tls_error, ps);
	} else {
		ps->raw_connection = purple_proxy_connect(ps->gc, account,
			ps->host, ps->port, _purple_socket_connected_raw, ps);
	}

	if (ps->tls_connection == NULL &&
		ps->raw_connection == NULL)
	{
		ps->state = PURPLE_SOCKET_STATE_ERROR;
		return FALSE;
	}

	return TRUE;
}

gssize
purple_socket_read(PurpleSocket *ps, guchar *buf, size_t len)
{
	g_return_val_if_fail(ps != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTED))
		return -1;

	if (ps->is_tls)
		return purple_ssl_read(ps->tls_connection, buf, len);
	else
		return read(ps->fd, buf, len);
}

gssize
purple_socket_write(PurpleSocket *ps, const guchar *buf, size_t len)
{
	g_return_val_if_fail(ps != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTED))
		return -1;

	if (ps->is_tls)
		return purple_ssl_write(ps->tls_connection, buf, len);
	else
		return write(ps->fd, buf, len);
}

void
purple_socket_watch(PurpleSocket *ps, PurpleInputCondition cond,
	PurpleInputFunction func, gpointer user_data)
{
	g_return_if_fail(ps != NULL);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTED))
		return;

	if (ps->inpa > 0)
		purple_input_remove(ps->inpa);
	ps->inpa = 0;

	g_return_if_fail(ps->fd > 0);

	if (func != NULL)
		ps->inpa = purple_input_add(ps->fd, cond, func, user_data);
}

int
purple_socket_get_fd(PurpleSocket *ps)
{
	g_return_val_if_fail(ps != NULL, -1);

	if (!purple_socket_check_state(ps, PURPLE_SOCKET_STATE_CONNECTED))
		return -1;

	g_return_val_if_fail(ps->fd > 0, -1);

	return ps->fd;
}

void
purple_socket_set_data(PurpleSocket *ps, const gchar *key, gpointer data)
{
	g_return_if_fail(ps != NULL);
	g_return_if_fail(key != NULL);

	if (data == NULL)
		g_hash_table_remove(ps->data, key);
	else
		g_hash_table_insert(ps->data, g_strdup(key), data);
}

gpointer
purple_socket_get_data(PurpleSocket *ps, const gchar *key)
{
	g_return_val_if_fail(ps != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	return g_hash_table_lookup(ps->data, key);
}

static void
purple_socket_cancel(PurpleSocket *ps)
{
	if (ps->inpa > 0)
		purple_input_remove(ps->inpa);
	ps->inpa = 0;

	if (ps->tls_connection != NULL) {
		purple_ssl_close(ps->tls_connection);
		ps->fd = -1;
	}
	ps->tls_connection = NULL;

	if (ps->raw_connection != NULL)
		purple_proxy_connect_cancel(ps->raw_connection);
	ps->raw_connection = NULL;

	if (ps->fd > 0)
		close(ps->fd);
	ps->fd = 0;
}

void
purple_socket_destroy(PurpleSocket *ps)
{
	if (ps == NULL)
		return;

	handle_remove(ps);

	purple_socket_cancel(ps);

	g_free(ps->host);
	g_hash_table_destroy(ps->data);
	g_free(ps);
}

void
_purple_socket_cancel_with_connection(PurpleConnection *gc)
{
	GSList *it;

	it = g_hash_table_lookup(handles, gc);
	for (; it; it = g_slist_next(it)) {
		PurpleSocket *ps = it->data;
		purple_socket_cancel(ps);
	}
}
