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

#include <string.h>

#include "account.h"
#include "glibcompat.h"

#include "api.h"
#include "data.h"

struct _FbDataPrivate
{
	FbApi *api;
	PurpleConnection *gc;
	PurpleRoomlist *roomlist;
	GQueue *msgs;
	GHashTable *icons;
	GHashTable *icona;
	guint syncev;
};

static const gchar *fb_props_strs[] = {
	"cid",
	"did",
	"stoken",
	"token"
};

static void
fb_data_icon_free(FbDataIcon *icon);

G_DEFINE_TYPE(FbData, fb_data, G_TYPE_OBJECT);

static void
fb_data_dispose(GObject *obj)
{
	FbDataPrivate *priv = FB_DATA(obj)->priv;

	if (priv->syncev > 0) {
		purple_timeout_remove(priv->syncev);
	}

	if (G_LIKELY(priv->api != NULL)) {
		g_object_unref(priv->api);
	}

	g_queue_free_full(priv->msgs, (GDestroyNotify) fb_api_message_free);
	g_hash_table_destroy(priv->icons);
	g_hash_table_destroy(priv->icona);
}

static void
fb_data_class_init(FbDataClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);

	gklass->dispose = fb_data_dispose;
	g_type_class_add_private(klass, sizeof (FbDataPrivate));
}

static void
fb_data_init(FbData *fata)
{
	FbDataPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(fata, FB_TYPE_DATA, FbDataPrivate);
	fata->priv = priv;

	priv->msgs = g_queue_new();
	priv->icons = g_hash_table_new_full(g_direct_hash, g_direct_equal,
	                                    (GDestroyNotify) fb_data_icon_free,
					    NULL);
	priv->icona = g_hash_table_new_full(g_direct_hash, g_direct_equal,
	                                    (GDestroyNotify) fb_data_icon_free,
					    NULL);
}

FbData *
fb_data_new(PurpleConnection *gc)
{
	FbData *fata;
	FbDataPrivate *priv;

	fata = g_object_new(FB_TYPE_DATA, NULL);
	priv = fata->priv;

	priv->api = fb_api_new(gc);
	priv->gc = gc;

	return fata;
}

gboolean
fb_data_load(FbData *fata)
{
	const gchar *str;
	FbDataPrivate *priv;
	FbId id;
	gboolean ret = TRUE;
	guint i;
	guint64 uint;
	GValue val = G_VALUE_INIT;
	PurpleAccount *acct;

	g_return_val_if_fail(FB_IS_DATA(fata), FALSE);
	priv = fata->priv;
	acct = purple_connection_get_account(priv->gc);

	for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
		str = purple_account_get_string(acct, fb_props_strs[i], NULL);

		if (str == NULL) {
			ret = FALSE;
		}

		g_value_init(&val, G_TYPE_STRING);
		g_value_set_string(&val, str);
		g_object_set_property(G_OBJECT(priv->api), fb_props_strs[i],
		                      &val);
		g_value_unset(&val);
	}

	str = purple_account_get_string(acct, "mid", NULL);

	if (str != NULL) {
		uint = g_ascii_strtoull(str, NULL, 10);
		g_value_init(&val, G_TYPE_UINT64);
		g_value_set_uint64(&val, uint);
		g_object_set_property(G_OBJECT(priv->api), "mid", &val);
		g_value_unset(&val);
	} else {
		ret = FALSE;
	}

	str = purple_account_get_string(acct, "uid", NULL);

	if (str != NULL) {
		id = FB_ID_FROM_STR(str);
		g_value_init(&val, FB_TYPE_ID);
		g_value_set_int64(&val, id);
		g_object_set_property(G_OBJECT(priv->api), "uid", &val);
		g_value_unset(&val);
	} else {
		ret = FALSE;
	}

	fb_api_rehash(priv->api);
	return ret;
}

void
fb_data_save(FbData *fata)
{
	const gchar *str;
	FbDataPrivate *priv;
	gchar *dup;
	guint i;
	guint64 uint;
	GValue val = G_VALUE_INIT;
	PurpleAccount *acct;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;
	acct = purple_connection_get_account(priv->gc);

	for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
		g_value_init(&val, G_TYPE_STRING);
		g_object_get_property(G_OBJECT(priv->api), fb_props_strs[i],
		                      &val);
		str = g_value_get_string(&val);
		purple_account_set_string(acct, fb_props_strs[i], str);
		g_value_unset(&val);
	}

	g_value_init(&val, G_TYPE_UINT64);
	g_object_get_property(G_OBJECT(priv->api), "mid", &val);
	uint = g_value_get_uint64(&val);
	g_value_unset(&val);

	dup = g_strdup_printf("%" G_GINT64_FORMAT, uint);
	purple_account_set_string(acct, "mid", dup);
	g_free(dup);

	g_value_init(&val, G_TYPE_INT64);
	g_object_get_property(G_OBJECT(priv->api), "uid", &val);
	uint = g_value_get_int64(&val);
	g_value_unset(&val);

	dup = g_strdup_printf("%" FB_ID_FORMAT, uint);
	purple_account_set_string(acct, "uid", dup);
	g_free(dup);
}

void
fb_data_add_sync_timeout(FbData *fata, guint minutes, GSourceFunc func,
                         gpointer data)
{
	FbDataPrivate *priv;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;

	if (priv->syncev > 0) {
		purple_timeout_remove(priv->syncev);
	}

	minutes *= 60;
	priv->syncev = purple_timeout_add_seconds(minutes, func, data);
}

void
fb_data_clear_sync_timeout(FbData *fata, gboolean remove)
{
	FbDataPrivate *priv;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;
	g_return_if_fail(priv->syncev > 0);

	if (remove) {
		purple_timeout_remove(priv->syncev);
	}

	priv->syncev = 0;
}

FbApi *
fb_data_get_api(FbData *fata)
{
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;

	return priv->api;
}

PurpleConnection *
fb_data_get_connection(FbData *fata)
{
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;

	return priv->gc;
}

PurpleRoomlist *
fb_data_get_roomlist(FbData *fata)
{
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;

	return priv->roomlist;
}

void
fb_data_set_roomlist(FbData *fata, PurpleRoomlist *list)
{
	FbDataPrivate *priv;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;

	priv->roomlist = list;
}

void
fb_data_add_message(FbData *fata, FbApiMessage *msg)
{
	FbDataPrivate *priv;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;

	g_queue_push_tail(priv->msgs, msg);
}

GSList *
fb_data_take_messages(FbData *fata, FbId uid)
{
	FbApiMessage *msg;
	FbDataPrivate *priv;
	GList *l;
	GList *prev;
	GSList *msgs = NULL;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;
	l = priv->msgs->tail;

	while (l != NULL) {
		msg = l->data;
		prev = l->prev;

		if (msg->uid == uid) {
			msgs = g_slist_prepend(msgs, msg);
			g_queue_delete_link(priv->msgs, l);
		}

		l = prev;
	}

	return msgs;
}

FbDataIcon *
fb_data_icon_add(FbData *fata, PurpleBuddy *buddy, const gchar *url,
                 PurpleHttpCallback func)
{
	FbDataIcon *icon;
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	g_return_val_if_fail(PURPLE_IS_BUDDY(buddy), NULL);
	g_return_val_if_fail(url != NULL, NULL);
	priv = fata->priv;

	icon = g_new(FbDataIcon, 1);
	icon->fata = fata;
	icon->buddy = buddy;
	icon->url = g_strdup(url);
	icon->func = func;

	g_hash_table_replace(priv->icons, icon, icon);
	return icon;
}

static void
fb_data_icon_free(FbDataIcon *icon)
{
	g_return_if_fail(icon != NULL);

	g_free(icon->url);
	g_free(icon);
}

void
fb_data_icon_destroy(FbDataIcon *icon)
{
	FbDataPrivate *priv;

	g_return_if_fail(icon != NULL);
	g_return_if_fail(FB_IS_DATA(icon->fata));
	priv = icon->fata->priv;

	if (!g_hash_table_remove(priv->icons, icon) &&
	    !g_hash_table_remove(priv->icona, icon))
	{
		fb_data_icon_free(icon);
	}
}

static void
fb_data_icon_cb(PurpleHttpConnection *con, PurpleHttpResponse *res,
                gpointer data)
{
	FbDataIcon *icon = data;
	FbData *fata = icon->fata;

	if (icon->func != NULL) {
		icon->func(con, res, icon);
	}

	fb_data_icon_destroy(icon);
	fb_data_icon_queue(fata);
}

void
fb_data_icon_queue(FbData *fata)
{
	FbDataIcon *icon;
	FbDataPrivate *priv;
	GHashTableIter iter;
	guint size;
	PurpleAccount *acct;
	PurpleConnection *gc;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;
	size = g_hash_table_size(priv->icona);

	if (size >= FB_DATA_ICON_MAX) {
		return;
	}

	g_hash_table_iter_init(&iter, priv->icons);

	while (g_hash_table_iter_next(&iter, (gpointer*) &icon, NULL)) {
		acct = purple_buddy_get_account(icon->buddy);
		gc = purple_account_get_connection(acct);

		if (g_hash_table_lookup_extended(priv->icona, icon, NULL, NULL)) {
			continue;
		}

		g_hash_table_iter_steal(&iter);
		g_hash_table_replace(priv->icona, icon, icon);
		purple_http_get(gc, fb_data_icon_cb, icon, icon->url);

		if (++size >= FB_DATA_ICON_MAX) {
			break;
		}
	}
}
