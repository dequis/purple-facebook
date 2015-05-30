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

#include "facebook.h"

static PurpleProtocol *my_protocol = NULL;

static void
fb_login(PurpleAccount *acct)
{

}

static void
fb_close(PurpleConnection *gc)
{

}

static GList *
fb_status_types(PurpleAccount *acct)
{
	return NULL;
}

static const char *
fb_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "facebook";
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
facebook_protocol_client_iface_init(PurpleProtocolClientIface *client_iface)
{

}

static void
facebook_protocol_server_iface_init(PurpleProtocolServerIface *server_iface)
{

}

static void
facebook_protocol_im_iface_init(PurpleProtocolIMIface *im_iface)
{

}

static void
facebook_protocol_chat_iface_init(PurpleProtocolChatIface *chat_iface)
{

}

static void
facebook_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *privacy_iface)
{

}

static void
facebook_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *roomlist_iface)
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
