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

#include "internal.h"

#include "account.h"
#include "connection.h"
#include "plugins.h"
#include "protocol.h"
#include "protocols.h"
#include "roomlist.h"
#include "version.h"

#include "api.h"
#include "facebook.h"

static const gchar *fb_props_strs[] = {
	"cid",
	"cuid",
	"stoken",
	"token"
};

static PurpleProtocol *my_protocol = NULL;

static gboolean
fb_props_load(PurpleConnection *gc)
{
	const gchar *str;
	FbApi *api;
	FbId id;
	gboolean ret = TRUE;
	guint i;
	guint64 uint;
	GValue val = G_VALUE_INIT;
	PurpleAccount *acct;

	acct = purple_connection_get_account(gc);
	api = purple_connection_get_protocol_data(gc);
	g_return_val_if_fail(FB_IS_API(api), FALSE);

	for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
		str = purple_account_get_string(acct, fb_props_strs[i], NULL);

		if (str == NULL) {
			ret = FALSE;
		}

		g_value_init(&val, G_TYPE_STRING);
		g_value_set_string(&val, str);
		g_object_set_property(G_OBJECT(api), fb_props_strs[i], &val);
		g_value_unset(&val);
	}

	str = purple_account_get_string(acct, "mid", NULL);

	if (str != NULL) {
		uint = g_ascii_strtoull(str, NULL, 10);
		g_value_init(&val, G_TYPE_UINT64);
		g_value_set_uint64(&val, uint);
		g_object_set_property(G_OBJECT(api), "mid", &val);
		g_value_unset(&val);
	} else {
		ret = FALSE;
	}

	str = purple_account_get_string(acct, "uid", NULL);

	if (str != NULL) {
		id = FB_ID_FROM_STR(str);
		g_value_init(&val, FB_TYPE_ID);
		g_value_set_int64(&val, id);
		g_object_set_property(G_OBJECT(api), "uid", &val);
		g_value_unset(&val);
	} else {
		ret = FALSE;
	}

	fb_api_rehash(api);
	return ret;
}

static void
fb_props_save(PurpleConnection *gc)
{
	const gchar *str;
	FbApi *api;
	gchar *dup;
	guint i;
	guint64 uint;
	GValue val = G_VALUE_INIT;
	PurpleAccount *acct;

	acct = purple_connection_get_account(gc);
	api = purple_connection_get_protocol_data(gc);
	g_return_if_fail(FB_IS_API(api));

	for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
		g_value_init(&val, G_TYPE_STRING);
		g_object_get_property(G_OBJECT(api), fb_props_strs[i], &val);
		str = g_value_get_string(&val);
		purple_account_set_string(acct, fb_props_strs[i], str);
		g_value_unset(&val);
	}

	g_value_init(&val, G_TYPE_UINT64);
	g_object_get_property(G_OBJECT(api), "mid", &val);
	uint = g_value_get_uint64(&val);
	g_value_unset(&val);

	dup = g_strdup_printf("%" G_GINT64_FORMAT, uint);
	purple_account_set_string(acct, "mid", dup);
	g_free(dup);

	g_value_init(&val, G_TYPE_INT64);
	g_object_get_property(G_OBJECT(api), "uid", &val);
	uint = g_value_get_int64(&val);
	g_value_unset(&val);

	dup = g_strdup_printf("%" FB_ID_FORMAT, uint);
	purple_account_set_string(acct, "uid", dup);
	g_free(dup);
}

static void
fb_cb_api_auth(FbApi *api, gpointer data)
{
	PurpleConnection *gc = data;

	purple_connection_update_progress(gc, _("Fetching contacts"), 2, 4);
	fb_props_save(gc);
	fb_api_contacts(api);
}

static void
fb_cb_api_connect(FbApi *api, gpointer data)
{
	PurpleConnection *gc = data;

	fb_props_save(gc);
	purple_connection_set_state(gc, PURPLE_CONNECTION_CONNECTED);
}

static void
fb_cb_api_contacts(FbApi *api, GSList *users, gpointer data)
{
	FbApiUser *user;
	gchar uid[FB_ID_STRMAX];
	GSList *l;
	PurpleAccount *acct;
	PurpleBuddy *bdy;
	PurpleConnection *gc = data;
	PurpleGroup *grp;

	acct = purple_connection_get_account(gc);
	grp = purple_blist_get_default_group();

	for (l = users; l != NULL; l = l->next) {
		user = l->data;
		FB_ID_TO_STR(user->uid, uid);

		if (purple_blist_find_buddy(acct, uid) == NULL) {
			bdy = purple_buddy_new(acct, uid, user->name);
			purple_blist_add_buddy(bdy, NULL, grp, NULL);
		}
	}

	purple_connection_update_progress(gc, _("Connecting"), 3, 4);
	fb_api_connect(api);
}

static void
fb_cb_api_error(FbApi *api, GError *error, gpointer data)
{
	PurpleConnection *gc = data;

	purple_connection_error(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
	                        error->message);
}

static void
fb_cb_api_message(FbApi *api, GSList *msgs, gpointer data)
{
	FbApiMessage *msg;
	gchar uid[FB_ID_STRMAX];
	GSList *l;
	PurpleConnection *gc = data;

	for (l = msgs; l != NULL; l = l->next) {
		msg = l->data;
		FB_ID_TO_STR(msg->uid, uid);
		purple_serv_got_im(gc, uid, msg->text, PURPLE_MESSAGE_RECV, time(NULL));
	}
}

static void
fb_cb_api_presence(FbApi *api, GSList *press, gpointer data)
{
	const gchar *statid;
	FbApiPresence *pres;
	gchar uid[FB_ID_STRMAX];
	GSList *l;
	PurpleAccount *acct;
	PurpleBuddy *bdy;
	PurpleConnection *gc = data;
	PurplePresence *ppres;
	PurpleStatusPrimitive pstat;

	acct = purple_connection_get_account(gc);

	for (l = press; l != NULL; l = l->next) {
		pres = l->data;

		FB_ID_TO_STR(pres->uid, uid);
		bdy = purple_blist_find_buddy(acct, uid);
		ppres = purple_buddy_get_presence(bdy);

		if (G_UNLIKELY(bdy == NULL)) {
			continue;
		}

		if (pres->active) {
			pstat = PURPLE_STATUS_AVAILABLE;
		} else {
			pstat = PURPLE_STATUS_OFFLINE;
		}

		statid = purple_primitive_get_id_from_type(pstat);
		purple_presence_switch_status(ppres, statid);
	}
}

static void
fb_cb_api_thread_create(FbApi *api, FbId tid, gpointer data)
{
	purple_debug_info(NULL, "fb_cb_api_thread_create()");
}

static void
fb_cb_api_thread_info(FbApi *api, FbApiThread *thrd, gpointer data)
{
	purple_debug_info(NULL, "fb_cb_api_thread_info()");
}

static void
fb_cb_api_thread_list(FbApi *api, GSList *thrds, gpointer data)
{
	purple_debug_info(NULL, "fb_cb_api_thread_list()");
}

static void
fb_cb_api_typing(FbApi *api, FbApiTyping *typg, gpointer data)
{
	gchar uid[FB_ID_STRMAX];
	PurpleConnection *gc = data;

	FB_ID_TO_STR(typg->uid, uid);

	if (typg->state) {
		purple_serv_got_typing(gc, uid, 0, PURPLE_IM_TYPING);
	} else {
		purple_serv_got_typing_stopped(gc, uid);
	}
}

static void
fb_login(PurpleAccount *acct)
{
	const gchar *pass;
	const gchar *user;
	FbApi *api;
	PurpleConnection *gc;

	gc = purple_account_get_connection(acct);
	//purple_connection_set_flags(gc, );

	if (!purple_ssl_is_supported()) {
		purple_connection_error(gc,
			PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
			_("SSL support unavailable"));
		return;
	}

	api = fb_api_new(gc);
	purple_connection_set_protocol_data(gc, api);

	g_signal_connect(api,
	                 "auth",
	                 G_CALLBACK(fb_cb_api_auth),
	                 gc);
	g_signal_connect(api,
	                 "connect",
	                 G_CALLBACK(fb_cb_api_connect),
	                 gc);
	g_signal_connect(api,
	                 "contacts",
	                 G_CALLBACK(fb_cb_api_contacts),
	                 gc);
	g_signal_connect(api,
	                 "error",
	                 G_CALLBACK(fb_cb_api_error),
	                 gc);
	g_signal_connect(api,
	                 "message",
	                 G_CALLBACK(fb_cb_api_message),
	                 gc);
	g_signal_connect(api,
	                 "presence",
	                 G_CALLBACK(fb_cb_api_presence),
	                 gc);
	g_signal_connect(api,
	                 "thread-create",
	                 G_CALLBACK(fb_cb_api_thread_create),
	                 gc);
	g_signal_connect(api,
	                 "thread-info",
	                 G_CALLBACK(fb_cb_api_thread_info),
	                 gc);
	g_signal_connect(api,
	                 "thread-list",
	                 G_CALLBACK(fb_cb_api_thread_list),
	                 gc);
	g_signal_connect(api,
	                 "typing",
	                 G_CALLBACK(fb_cb_api_typing),
	                 gc);

	if (!fb_props_load(gc)) {
		user = purple_account_get_username(acct);
		pass = purple_connection_get_password(gc);
		purple_connection_update_progress(gc, _("Authenticating"),
		                                  1, 4);
		fb_api_auth(api, user, pass);
		return;
	}

	purple_connection_update_progress(gc, _("Fetching contacts"), 2, 4);
	fb_api_contacts(api);
}

static void
fb_close(PurpleConnection *gc)
{
	FbApi *api;

	api = purple_connection_get_protocol_data(gc);
	g_return_if_fail(FB_IS_API(api));

	fb_api_disconnect(api);
	g_object_unref(api);
	purple_connection_set_protocol_data(gc, NULL);
}

static GList *
fb_status_types(PurpleAccount *acct)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new(PURPLE_STATUS_AVAILABLE,
	                              NULL, NULL, FALSE);
	types = g_list_prepend(types, type);

	type = purple_status_type_new(PURPLE_STATUS_OFFLINE,
	                              NULL, NULL, FALSE);
	types = g_list_prepend(types, type);

	return types;
}

static const char *
fb_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "facebook";
}

static gint
fb_send(PurpleConnection *gc, PurpleMessage *msg)
{
	const gchar *name;
	const gchar *text;
	FbApi *api;
	FbId uid;

	api = purple_connection_get_protocol_data(gc);
	name = purple_message_get_recipient(msg);
	uid = FB_ID_FROM_STR(name);

	text = purple_message_get_contents(msg);
	fb_api_message(api, uid, FALSE, text);
	return 1;
}

static guint
fb_send_typing(PurpleConnection *gc, const gchar *name,
               PurpleIMTypingState state)
{
	FbApi *api;
	FbId uid;

	api = purple_connection_get_protocol_data(gc);
	uid = FB_ID_FROM_STR(name);
	fb_api_typing(api, uid, state != PURPLE_IM_NOT_TYPING);
	return 0;
}

static void
facebook_protocol_init(PurpleProtocol *protocol)
{
	protocol->id   = "prpl-facebook";
	protocol->name = "Facebook";
}

static void
facebook_protocol_class_init(PurpleProtocolClass *klass)
{
	klass->login        = fb_login;
	klass->close        = fb_close;
	klass->status_types = fb_status_types;
	klass->list_icon    = fb_list_icon;
}

static void
facebook_protocol_client_iface_init(PurpleProtocolClientIface *iface)
{

}

static void
facebook_protocol_server_iface_init(PurpleProtocolServerIface *iface)
{

}

static void
facebook_protocol_im_iface_init(PurpleProtocolIMIface *iface)
{
	iface->send        = fb_send;
	iface->send_typing = fb_send_typing;
}

static void
facebook_protocol_chat_iface_init(PurpleProtocolChatIface *iface)
{

}

static void
facebook_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *iface)
{

}

static void
facebook_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *iface)
{

}

PURPLE_DEFINE_TYPE_EXTENDED(
	FacebookProtocol, facebook_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  facebook_protocol_client_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  facebook_protocol_server_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  facebook_protocol_im_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  facebook_protocol_chat_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  facebook_protocol_privacy_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  facebook_protocol_roomlist_iface_init)
);

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          "prpl-facebook",
		"name",        "Facebook Protocol",
		"version",     DISPLAY_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Facebook Protocol Plugin"),
		"description", N_("Facebook Protocol Plugin"),
		"website",     PURPLE_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	facebook_protocol_register_type(plugin);
	my_protocol = purple_protocols_add(FACEBOOK_TYPE_PROTOCOL, error);
	return my_protocol != NULL;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	return purple_protocols_remove(my_protocol, error);
}

PURPLE_PLUGIN_INIT(facebook, plugin_query, plugin_load, plugin_unload);
