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
#include "data.h"
#include "facebook.h"
#include "util.h"

static PurpleProtocol *my_protocol = NULL;

static void
fb_cb_api_error(FbApi *api, GError *error, gpointer data);

static void
fb_cb_api_auth(FbApi *api, gpointer data)
{
	FbData *fata = data;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);

	purple_connection_update_progress(gc, _("Fetching contacts"), 2, 4);
	fb_data_save(fata);
	fb_api_contacts(api);
}

static void
fb_cb_api_connect(FbApi *api, gpointer data)
{
	FbData *fata = data;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);

	fb_data_save(fata);
	purple_connection_set_state(gc, PURPLE_CONNECTION_CONNECTED);
}

static void
fb_cb_data_icon(PurpleHttpConnection *con, PurpleHttpResponse *res,
                gpointer data)
{
	const gchar *csum;
	const gchar *name;
	const gchar *str;
	FbDataIcon *icon = data;
	FbHttpParams *params;
	GError *err = NULL;
	gsize size;
	guchar *idata;
	PurpleAccount *acct;
	PurpleHttpRequest *req;

	acct = purple_buddy_get_account(icon->buddy);
	name = purple_buddy_get_name(icon->buddy);

	if (!fb_http_error_chk(res, &err)) {
		fb_util_debug_warning("Failed to retrieve icon for %s: %s",
		                      name, err->message);
		g_error_free(err);
		return;
	}

	req = purple_http_conn_get_request(con);
	str = purple_http_request_get_url(req);
	params = fb_http_params_new_parse(str, TRUE);
	csum = fb_http_params_get_str(params, "oh", &err);
	str = purple_http_response_get_data(res, &size);

	idata = g_memdup(str, size);
	purple_buddy_icons_set_for_user(acct, name, idata, size, csum);
	fb_http_params_free(params);
}

static void
fb_cb_api_contacts(FbApi *api, GSList *users, gpointer data)
{
	const gchar *alias;
	const gchar *csum;
	FbApiUser *user;
	FbData *fata = data;
	FbId muid;
	gchar uid[FB_ID_STRMAX];
	GSList *l;
	GValue val = G_VALUE_INIT;
	PurpleAccount *acct;
	PurpleBuddy *bdy;
	PurpleConnection *gc;
	PurpleGroup *grp;

	gc = fb_data_get_connection(fata);
	acct = purple_connection_get_account(gc);
	grp = purple_blist_get_default_group();
	alias = purple_account_get_private_alias(acct);

	g_value_init(&val, FB_TYPE_ID);
	g_object_get_property(G_OBJECT(api), "uid", &val);
	muid = g_value_get_int64(&val);
	g_value_unset(&val);

	for (l = users; l != NULL; l = l->next) {
		user = l->data;
		FB_ID_TO_STR(user->uid, uid);

		if (G_UNLIKELY(user->uid == muid)) {
			if (G_UNLIKELY(alias != NULL)) {
				continue;
			}

			purple_account_set_private_alias(acct, user->name);
			continue;
		}

		bdy = purple_blist_find_buddy(acct, uid);

		if (bdy == NULL) {
			bdy = purple_buddy_new(acct, uid, user->name);
			purple_blist_add_buddy(bdy, NULL, grp, NULL);
			fb_data_icon_add(fata, bdy, user->icon,
			                 fb_cb_data_icon);
			continue;
		}

		csum = purple_buddy_icons_get_checksum_for_user(bdy);

		if (!purple_strequal(csum, user->csum)) {
			fb_data_icon_add(fata, bdy, user->icon,
			                 fb_cb_data_icon);
		}
	}

	fb_data_icon_queue(fata);
	purple_connection_update_progress(gc, _("Connecting"), 3, 4);
	fb_api_connect(api);
}

static void
fb_cb_api_error(FbApi *api, GError *error, gpointer data)
{
	FbData *fata = data;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);
	purple_connection_error(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
	                        error->message);
}

static void
fb_cb_api_message(FbApi *api, GSList *msgs, gpointer data)
{
	FbApiMessage *msg;
	FbData *fata = data;
	gchar tid[FB_ID_STRMAX];
	gchar uid[FB_ID_STRMAX];
	gint id;
	GSList *l;
	PurpleAccount *acct;
	PurpleChatConversation *chat;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);
	acct = purple_connection_get_account(gc);

	for (l = msgs; l != NULL; l = l->next) {
		msg = l->data;
		chat = NULL;
		FB_ID_TO_STR(msg->uid, uid);

		if (msg->tid == 0) {
			purple_serv_got_im(gc, uid, msg->text,
		                           PURPLE_MESSAGE_RECV,
			                   time(NULL));
			continue;
		}

		FB_ID_TO_STR(msg->tid, tid);
		chat = purple_conversations_find_chat_with_account(tid, acct);

		if (chat != NULL) {
			id = purple_chat_conversation_get_id(chat);
			purple_serv_got_chat_in(gc, id, uid,
			                        PURPLE_MESSAGE_RECV,
		                                msg->text, time(NULL));
		}
	}
}

static void
fb_cb_api_presence(FbApi *api, GSList *press, gpointer data)
{
	const gchar *statid;
	FbApiPresence *pres;
	FbData *fata = data;
	gchar uid[FB_ID_STRMAX];
	GSList *l;
	PurpleAccount *acct;
	PurpleConnection *gc;
	PurpleStatusPrimitive pstat;

	gc = fb_data_get_connection(fata);
	acct = purple_connection_get_account(gc);

	for (l = press; l != NULL; l = l->next) {
		pres = l->data;

		if (pres->active) {
			pstat = PURPLE_STATUS_AVAILABLE;
		} else {
			pstat = PURPLE_STATUS_OFFLINE;
		}

		FB_ID_TO_STR(pres->uid, uid);
		statid = purple_primitive_get_id_from_type(pstat);
		purple_protocol_got_user_status(acct, uid, statid, NULL);
	}
}

static void
fb_cb_api_thread_create(FbApi *api, FbId tid, gpointer data)
{
	FbData *fata = data;
	gchar sid[FB_ID_STRMAX];
	GHashTable *table;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);
	FB_ID_TO_STR(tid, sid);

	table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	g_hash_table_insert(table, "name", g_strdup(sid));
	purple_serv_join_chat(gc, table);
	g_hash_table_destroy(table);
}

static void
fb_cb_api_thread_info(FbApi *api, FbApiThread *thrd, gpointer data)
{
	FbApiUser *user;
	FbData *fata = data;
	gchar tid[FB_ID_STRMAX];
	gchar uid[FB_ID_STRMAX];
	gint id;
	GSList *l;
	PurpleChatConversation *chat;
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);
	id = fb_data_get_chatid(fata);
	FB_ID_TO_STR(thrd->tid, tid);

	chat = purple_serv_got_joined_chat(gc, id, tid);
	purple_chat_conversation_set_topic(chat, NULL, thrd->topic);

	for (l = thrd->users; l != NULL; l = l->next) {
		user = l->data;
		FB_ID_TO_STR(user->uid, uid);
		purple_chat_conversation_add_user(chat, uid, NULL, 0, FALSE);
	}
}

static void
fb_cb_api_thread_list(FbApi *api, GSList *thrds, gpointer data)
{
	FbApiUser *user;
	FbData *fata = data;
	gchar tid[FB_ID_STRMAX];
	GSList *l;
	GSList *m;
	GString *gstr;
	FbApiThread *thrd;
	PurpleRoomlist *list;
	PurpleRoomlistRoom *room;

	list = fb_data_get_roomlist(fata);
	gstr = g_string_new(NULL);

	for (l = thrds; l != NULL; l = l->next) {
		thrd = l->data;
		FB_ID_TO_STR(thrd->tid, tid);
		g_string_truncate(gstr, 0);

		for (m = thrd->users; m != NULL; m = m->next) {
			user = m->data;

			if (gstr->len > 0) {
				g_string_append(gstr, ", ");
			}

			g_string_append(gstr, user->name);
		}

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM,
		                                tid, NULL);
		purple_roomlist_room_add_field(list, room, thrd->topic);
		purple_roomlist_room_add_field(list, room, gstr->str);
		purple_roomlist_room_add(list, room);
	}

	purple_roomlist_set_in_progress(list, FALSE);
	g_string_free(gstr, TRUE);
}

static void
fb_cb_api_typing(FbApi *api, FbApiTyping *typg, gpointer data)
{
	FbData *fata = data;
	gchar uid[FB_ID_STRMAX];
	PurpleConnection *gc;

	gc = fb_data_get_connection(fata);
	FB_ID_TO_STR(typg->uid, uid);

	if (typg->state) {
		purple_serv_got_typing(gc, uid, 0, PURPLE_IM_TYPING);
	} else {
		purple_serv_got_typing_stopped(gc, uid);
	}
}

static void
fb_blist_chat_create(GSList *buddies, gpointer data)
{
	const gchar *name;
	FbApi *api;
	FbData *fata = data;
	FbId uid;
	gpointer mptr;
	GSList *l;
	GSList *uids = NULL;
	PurpleConnection *gc;
	PurpleRequestCommonParameters *cpar;

	gc = fb_data_get_connection(fata);
	api = fb_data_get_api(fata);

	if (g_slist_length(buddies) < 2) {
		cpar = purple_request_cpar_from_connection(gc);
		purple_notify_error(gc,
		                    _("Initiate Chat"),
		                    _("Failed to Initiate Chat"),
		                    _("At least two initial chat participants"
		                      " are required."),
				    cpar);
		return;
	}

	for (l = buddies; l != NULL; l = l->next) {
		name = purple_buddy_get_name(l->data);
		uid = FB_ID_FROM_STR(name);
		mptr = g_memdup(&uid, sizeof uid);
		uids = g_slist_prepend(uids, mptr);
	}

	fb_api_thread_create(api, uids);
	g_slist_free_full(uids, g_free);
}

static void
fb_blist_chat_init(PurpleBlistNode *node, gpointer data)
{
	FbData *fata = data;
	GSList *select = NULL;
	PurpleConnection *gc;

	if (G_OBJECT_TYPE(node) != PURPLE_TYPE_BUDDY) {
		return;
	}

	gc = fb_data_get_connection(fata);
	select = g_slist_prepend(select, PURPLE_BUDDY(node));

	fb_util_request_buddy(gc,
	                      _("Initiate Chat"),
	                      _("Initial Chat Participants"),
	                      _("Select at least two initial participants."),
	                      select, TRUE,
			      G_CALLBACK(fb_blist_chat_create), NULL,
			      fata);
	g_slist_free(select);
}

static void
fb_login(PurpleAccount *acct)
{
	const gchar *pass;
	const gchar *user;
	FbApi *api;
	FbData *fata;
	PurpleConnection *gc;

	gc = purple_account_get_connection(acct);
	//purple_connection_set_flags(gc, );

	if (!purple_ssl_is_supported()) {
		purple_connection_error(gc,
			PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
			_("SSL support unavailable"));
		return;
	}

	fata = fb_data_new(gc);
	api = fb_data_get_api(fata);
	purple_connection_set_protocol_data(gc, fata);

	g_signal_connect(api,
	                 "auth",
	                 G_CALLBACK(fb_cb_api_auth),
	                 fata);
	g_signal_connect(api,
	                 "connect",
	                 G_CALLBACK(fb_cb_api_connect),
	                 fata);
	g_signal_connect(api,
	                 "contacts",
	                 G_CALLBACK(fb_cb_api_contacts),
	                 fata);
	g_signal_connect(api,
	                 "error",
	                 G_CALLBACK(fb_cb_api_error),
	                 fata);
	g_signal_connect(api,
	                 "message",
	                 G_CALLBACK(fb_cb_api_message),
	                 fata);
	g_signal_connect(api,
	                 "presence",
	                 G_CALLBACK(fb_cb_api_presence),
	                 fata);
	g_signal_connect(api,
	                 "thread-create",
	                 G_CALLBACK(fb_cb_api_thread_create),
	                 fata);
	g_signal_connect(api,
	                 "thread-info",
	                 G_CALLBACK(fb_cb_api_thread_info),
	                 fata);
	g_signal_connect(api,
	                 "thread-list",
	                 G_CALLBACK(fb_cb_api_thread_list),
	                 fata);
	g_signal_connect(api,
	                 "typing",
	                 G_CALLBACK(fb_cb_api_typing),
	                 fata);

	if (!fb_data_load(fata)) {
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
	FbData *fata;

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);

	fb_api_disconnect(api);
	g_object_unref(fata);
	purple_connection_set_protocol_data(gc, NULL);
}

static GList *
fb_status_types(PurpleAccount *acct)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new(PURPLE_STATUS_AVAILABLE,
	                              NULL, NULL, TRUE);
	types = g_list_prepend(types, type);

	type = purple_status_type_new(PURPLE_STATUS_OFFLINE,
	                              NULL, NULL, TRUE);
	types = g_list_prepend(types, type);

	return types;
}

static const char *
fb_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "facebook";
}

static GList *
fb_client_blist_node_menu(PurpleBlistNode *node)
{
	FbData *fata;
	GList *acts = NULL;
	PurpleAccount *acct;
	PurpleConnection *gc;
	PurpleMenuAction *act;

	if (G_OBJECT_TYPE(node) != PURPLE_TYPE_BUDDY) {
		return NULL;
	}

	acct = purple_buddy_get_account(PURPLE_BUDDY(node));
	gc = purple_account_get_connection(acct);
	fata = purple_connection_get_protocol_data(gc);

	act = purple_menu_action_new(_("Initiate _Chat"),
	                             PURPLE_CALLBACK(fb_blist_chat_init),
	                             fata, NULL);
	acts = g_list_prepend(acts, act);

	return g_list_reverse(acts);
}

static gint
fb_im_send(PurpleConnection *gc, PurpleMessage *msg)
{
	const gchar *name;
	const gchar *text;
	FbApi *api;
	FbData *fata;
	FbId uid;

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);

	name = purple_message_get_recipient(msg);
	uid = FB_ID_FROM_STR(name);

	text = purple_message_get_contents(msg);
	fb_api_message(api, uid, FALSE, text);
	return 1;
}

static guint
fb_im_send_typing(PurpleConnection *gc, const gchar *name,
                  PurpleIMTypingState state)
{
	FbApi *api;
	FbData *fata;
	FbId uid;

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	uid = FB_ID_FROM_STR(name);

	fb_api_typing(api, uid, state != PURPLE_IM_NOT_TYPING);
	return 0;
}

static void
fb_chat_join(PurpleConnection *gc, GHashTable *data)
{
	const gchar *name;
	FbApi *api;
	FbData *fata;
	FbId tid;

	name = g_hash_table_lookup(data, "name");
	g_return_if_fail(name != NULL);

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	tid = FB_ID_FROM_STR(name);

	fb_api_thread_info(api, tid);
}

static void
fb_chat_invite(PurpleConnection *gc, gint id, const gchar *msg,
               const gchar *who)
{
	const gchar *name;
	FbApi *api;
	FbData *fata;
	FbId tid;
	FbId uid;
	PurpleChatConversation *chat;
	PurpleRequestCommonParameters *cpar;

	if (!FB_ID_IS_STR(who)) {
		cpar = purple_request_cpar_from_connection(gc);
		purple_notify_error(gc,
		                    _("Invite Buddy Into Chat Room"),
		                    _("Failed to Invite User"),
		                    _("Invalid Facebook identifier."),
				    cpar);
		return;
	}

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	chat = purple_conversations_find_chat(gc, id);

	name = purple_conversation_get_name(PURPLE_CONVERSATION(chat));
	tid = FB_ID_FROM_STR(name);
	uid = FB_ID_FROM_STR(who);

	purple_chat_conversation_add_user(chat, who, NULL, 0, TRUE);
	fb_api_thread_invite(api, tid, uid);
}

static gint
fb_chat_send(PurpleConnection *gc, gint id, PurpleMessage *msg)
{
	const gchar *name;
	const gchar *text;
	FbApi *api;
	FbData *fata;
	FbId tid;
	PurpleAccount *acct;
	PurpleChatConversation *chat;

	acct = purple_connection_get_account(gc);
	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	chat = purple_conversations_find_chat(gc, id);

	name = purple_conversation_get_name(PURPLE_CONVERSATION(chat));
	tid = FB_ID_FROM_STR(name);

	text = purple_message_get_contents(msg);
	fb_api_message(api, tid, TRUE, text);

	name = purple_account_get_username(acct);
	purple_serv_got_chat_in(gc, id, name,
				purple_message_get_flags(msg),
	                        purple_message_get_contents(msg),
	                        time(NULL));
	return 0;
}

static void
fb_chat_set_topic(PurpleConnection *gc, gint id, const gchar *topic)
{
	const gchar *name;
	FbApi *api;
	FbData *fata;
	FbId tid;
	PurpleAccount *acct;
	PurpleChatConversation *chat;

	acct = purple_connection_get_account(gc);
	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	chat = purple_conversations_find_chat(gc, id);

	name = purple_conversation_get_name(PURPLE_CONVERSATION(chat));
	tid = FB_ID_FROM_STR(name);

	name = purple_account_get_username(acct);
	purple_chat_conversation_set_topic(chat, name, topic);
	fb_api_thread_topic(api, tid, topic);
}

static PurpleRoomlist *
fb_roomlist_get_list(PurpleConnection *gc)
{
	FbApi *api;
	FbData *fata;
	GList *flds = NULL;
	PurpleAccount *acct;
	PurpleRoomlist *list;
	PurpleRoomlistField *fld;

	fata = purple_connection_get_protocol_data(gc);
	api = fb_data_get_api(fata);
	acct = purple_connection_get_account(gc);
	list = purple_roomlist_new(acct);
	fb_data_set_roomlist(fata, list);

	fld = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
	                                _("Topic"), "topic", FALSE);
	flds = g_list_prepend(flds, fld);

	fld = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
	                                _("Users"), "users", FALSE);
	flds = g_list_prepend(flds, fld);

	flds = g_list_reverse(flds);
	purple_roomlist_set_fields(list, flds);

	fb_api_thread_list(api);
	return list;
}

static void
fb_roomlist_cancel(PurpleRoomlist *list)
{
	FbData *fata;
	PurpleAccount *acct;
	PurpleConnection *gc;
	PurpleRoomlist *cist;

	acct = purple_roomlist_get_account(list);
	gc = purple_account_get_connection(acct);
	fata = purple_connection_get_protocol_data(gc);
	cist = fb_data_get_roomlist(fata);

	if (G_LIKELY(cist == list)) {
		fb_data_set_roomlist(fata, NULL);
	}

	purple_roomlist_set_in_progress(list, FALSE);
	g_object_unref(list);
}

static void
facebook_protocol_init(PurpleProtocol *protocol)
{
	protocol->id      = "prpl-facebook";
	protocol->name    = "Facebook";
	protocol->options = OPT_PROTO_CHAT_TOPIC;
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
	iface->blist_node_menu = fb_client_blist_node_menu;
}

static void
facebook_protocol_server_iface_init(PurpleProtocolServerIface *iface)
{

}

static void
facebook_protocol_im_iface_init(PurpleProtocolIMIface *iface)
{
	iface->send        = fb_im_send;
	iface->send_typing = fb_im_send_typing;
}

static void
facebook_protocol_chat_iface_init(PurpleProtocolChatIface *iface)
{
	iface->join      = fb_chat_join;
	iface->invite    = fb_chat_invite;
	iface->send      = fb_chat_send;
	iface->set_topic = fb_chat_set_topic;
}

static void
facebook_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *iface)
{

}

static void
facebook_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *iface)
{
	iface->get_list = fb_roomlist_get_list;
	iface->cancel   = fb_roomlist_cancel;
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
