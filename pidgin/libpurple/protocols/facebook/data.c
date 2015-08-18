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
	GHashTable *imgs;
	GHashTable *unread;
	GHashTable *evs;
};

struct _FbDataImagePrivate
{
	FbData *fata;
	gchar *url;
	FbDataImageFunc func;
	gpointer data;

	gboolean active;
	const guint8 *image;
	gsize size;
};

static const gchar *fb_props_strs[] = {
	"cid",
	"did",
	"stoken",
	"token"
};

G_DEFINE_TYPE(FbData, fb_data, G_TYPE_OBJECT);
G_DEFINE_TYPE(FbDataImage, fb_data_image, G_TYPE_OBJECT);

static void
fb_data_dispose(GObject *obj)
{
	FbDataPrivate *priv = FB_DATA(obj)->priv;
	GHashTableIter iter;
	gpointer ptr;

	g_hash_table_iter_init(&iter, priv->evs);

	while (g_hash_table_iter_next(&iter, NULL, &ptr)) {
		purple_timeout_remove(GPOINTER_TO_UINT(ptr));
	}

	if (G_LIKELY(priv->api != NULL)) {
		g_object_unref(priv->api);
	}

	g_queue_free_full(priv->msgs, (GDestroyNotify) fb_api_message_free);

	g_hash_table_destroy(priv->imgs);
	g_hash_table_destroy(priv->unread);
	g_hash_table_destroy(priv->evs);
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
	priv->imgs = g_hash_table_new_full(g_direct_hash, g_direct_equal,
	                                   g_object_unref, NULL);
	priv->unread = g_hash_table_new_full(fb_id_hash, fb_id_equal,
	                                     g_free, NULL);
	priv->evs = g_hash_table_new_full(g_str_hash, g_str_equal,
					  g_free, NULL);
}

static void
fb_data_image_dispose(GObject *obj)
{
	FbDataImage *img = FB_DATA_IMAGE(obj);
	FbDataImagePrivate *priv = img->priv;
	FbData *fata = priv->fata;

	g_free(priv->url);
	g_hash_table_steal(fata->priv->imgs, img);
}

static void
fb_data_image_class_init(FbDataImageClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);

	gklass->dispose = fb_data_image_dispose;
	g_type_class_add_private(klass, sizeof (FbDataImagePrivate));
}

static void
fb_data_image_init(FbDataImage *img)
{
	FbDataImagePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(img, FB_TYPE_DATA_IMAGE,
	                                   FbDataImagePrivate);
	img->priv = priv;
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
fb_data_add_timeout(FbData *fata, const gchar *name, guint interval,
                    GSourceFunc func, gpointer data)
{
	FbDataPrivate *priv;
	gchar *key;
	guint id;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;

	fb_data_clear_timeout(fata, name, TRUE);

	key = g_strdup(name);
	id = purple_timeout_add(interval, func, data);
	g_hash_table_replace(priv->evs, key, GUINT_TO_POINTER(id));
}

void
fb_data_clear_timeout(FbData *fata, const gchar *name, gboolean remove)
{
	FbDataPrivate *priv;
	gpointer ptr;
	guint id;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;

	ptr = g_hash_table_lookup(priv->evs, name);
	id = GPOINTER_TO_UINT(ptr);

	if ((id > 0) && remove) {
		purple_timeout_remove(id);
	}

	g_hash_table_remove(priv->evs, name);
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

gboolean
fb_data_get_unread(FbData *fata, FbId id)
{
	FbDataPrivate *priv;
	gpointer *ptr;

	g_return_val_if_fail(FB_IS_DATA(fata), FALSE);
	g_return_val_if_fail(id != 0, FALSE);
	priv = fata->priv;

	ptr = g_hash_table_lookup(priv->unread, &id);
	return GPOINTER_TO_INT(ptr);
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
fb_data_set_unread(FbData *fata, FbId id, gboolean unread)
{
	FbDataPrivate *priv;
	gpointer key;

	g_return_if_fail(FB_IS_DATA(fata));
	g_return_if_fail(id != 0);
	priv = fata->priv;

	if (!unread) {
		g_hash_table_remove(priv->unread, &id);
		return;
	}

	key = g_memdup(&id, sizeof id);
	g_hash_table_replace(priv->unread, key, GINT_TO_POINTER(unread));
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

FbDataImage *
fb_data_image_add(FbData *fata, const gchar *url, FbDataImageFunc func,
                  gpointer data)
{
	FbDataImage *img;
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	img = g_object_new(FB_TYPE_DATA_IMAGE, NULL);
	priv = img->priv;

	priv->fata = fata;
	priv->url = g_strdup(url);
	priv->func = func;
	priv->data = data;

	g_hash_table_insert(fata->priv->imgs, img, img);
	return img;
}

gboolean
fb_data_image_get_active(FbDataImage *img)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	return priv->active;
}

gpointer
fb_data_image_get_data(FbDataImage *img)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	return priv->data;
}

FbData *
fb_data_image_get_fata(FbDataImage *img)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	return priv->fata;
}

const guint8 *
fb_data_image_get_image(FbDataImage *img, gsize *size)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	if (size != NULL) {
		*size = priv->size;
	}

	return priv->image;
}

guint8 *
fb_data_image_dup_image(FbDataImage *img, gsize *size)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	if (size != NULL) {
		*size = priv->size;
	}

	if (priv->size < 1) {
		return NULL;
	}

	return g_memdup(priv->image, priv->size);
}

const gchar *
fb_data_image_get_url(FbDataImage *img)
{
	FbDataImagePrivate *priv;

	g_return_val_if_fail(FB_IS_DATA_IMAGE(img), NULL);
	priv = img->priv;

	return priv->url;
}

static void
fb_data_image_cb(PurpleHttpConnection *con, PurpleHttpResponse *res,
                 gpointer data)
{
	FbDataImage *img = data;
	FbDataImagePrivate *priv = img->priv;
	GError *err = NULL;

	fb_http_error_chk(res, &err);
	priv->image = (guint8*) purple_http_response_get_data(res, &priv->size);
	priv->func(img, err);

	if (G_UNLIKELY(err != NULL)) {
		g_error_free(err);
	}

	fb_data_image_queue(priv->fata);
	g_object_unref(img);
}

void
fb_data_image_queue(FbData *fata)
{
	const gchar *url;
	FbDataImage *img;
	FbDataPrivate *priv;
	GHashTableIter iter;
	guint active = 0;

	g_return_if_fail(FB_IS_DATA(fata));
	priv = fata->priv;
	g_hash_table_iter_init(&iter, priv->imgs);

	while (g_hash_table_iter_next(&iter, (gpointer*) &img, NULL)) {
		if (fb_data_image_get_active(img)) {
			active++;
		}
	}

	if (active >= FB_DATA_ICON_MAX) {
		return;
	}

	g_hash_table_iter_init(&iter, priv->imgs);

	while (g_hash_table_iter_next(&iter, (gpointer*) &img, NULL)) {
		if (fb_data_image_get_active(img)) {
			continue;
		}

		img->priv->active = TRUE;
		url = fb_data_image_get_url(img);
		purple_http_get(priv->gc, fb_data_image_cb, img, url);

		if (++active >= FB_DATA_ICON_MAX) {
			break;
		}
	}
}
