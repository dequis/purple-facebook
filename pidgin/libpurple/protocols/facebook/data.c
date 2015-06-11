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

#include "api.h"
#include "data.h"

struct _FbDataPrivate
{
	FbApi *api;
	PurpleConnection *gc;
	PurpleRoomlist *roomlist;
	gint chatid;
};

static const gchar *fb_props_strs[] = {
	"cid",
	"did",
	"stoken",
	"token"
};

G_DEFINE_TYPE(FbData, fb_data, G_TYPE_OBJECT);

static void
fb_data_dispose(GObject *obj)
{
	FbDataPrivate *priv = FB_DATA(obj)->priv;

	if (G_LIKELY(priv->api != NULL)) {
		g_object_unref(priv->api);
	}

	if (priv->roomlist != NULL) {
		g_object_unref(priv->roomlist);
	}
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

FbApi *
fb_data_get_api(FbData *fata)
{
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;

	return priv->api;
}

gint
fb_data_get_chatid(FbData *fata)
{
	FbDataPrivate *priv;

	g_return_val_if_fail(FB_IS_DATA(fata), NULL);
	priv = fata->priv;

	return priv->chatid++;
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
