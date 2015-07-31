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

#ifndef _PURPLE_COMPAT_H_
#define _PURPLE_COMPAT_H_

#include "accountopt.h"
#include "connection.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "request.h"

#undef purple_notify_error

#define PurpleChatConversation         PurpleConvChat
#define PurpleProtocolChatEntry        struct proto_chat_entry
#define PurpleIMTypingState            PurpleTypingState
#define PurpleMessage                  const gchar
#define PurpleProtocol                 void
#define PurpleRequestCommonParameters  void

#define PURPLE_CMD_FLAG_PROTOCOL_ONLY  PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_CMD_P_PROTOCOL          PURPLE_CMD_P_PRPL
#define PURPLE_CONNECTION_CONNECTED    PURPLE_CONNECTED
#define PURPLE_IM_NOT_TYPING           PURPLE_NOT_TYPING
#define PURPLE_IM_TYPING               PURPLE_TYPING

#define PURPLE_CHAT_CONVERSATION        purple_conversation_get_chat_data
#define PURPLE_CONVERSATION             purple_conv_chat_get_conversation
#define PURPLE_IS_ACCOUNT(a)            ((a) != NULL)
#define PURPLE_IS_BUDDY(b)              ((b) != NULL)
#define PURPLE_IS_CHAT_CONVERSATION(c)  ((c) != NULL)
#define PURPLE_IS_CONNECTION(c)         ((c) != NULL)

#define purple_account_get_private_alias        purple_account_get_alias
#define purple_account_set_private_alias        purple_account_set_alias
#define purple_blist_get_default_group()        NULL
#define purple_blist_find_buddies               purple_find_buddies
#define purple_blist_find_buddy                 purple_find_buddy
#define purple_buddy_set_server_alias           purple_blist_server_alias_buddy
#define purple_chat_conversation_add_user       purple_conv_chat_add_user
#define purple_chat_conversation_get_id         purple_conv_chat_get_id
#define purple_chat_conversation_has_user       purple_conv_chat_find_user
#define purple_chat_conversation_remove_user    purple_conv_chat_remove_user
#define purple_chat_conversation_set_topic      purple_conv_chat_set_topic
#define purple_connection_error                 purple_connection_error_reason
#define purple_connection_is_disconnecting(c)   FALSE
#define purple_conversation_get_connection      purple_conversation_get_gc
#define purple_protocol_got_user_status         purple_prpl_got_user_status
#define purple_proxy_info_get_proxy_type        purple_proxy_info_get_type
#define purple_request_cpar_from_connection(c)  NULL
#define purple_roomlist_get_account(l)          ((l)->account)
#define purple_serv_got_chat_in                 serv_got_chat_in
#define purple_serv_got_chat_left               serv_got_chat_left
#define purple_serv_got_im                      serv_got_im
#define purple_serv_got_typing                  serv_got_typing
#define purple_serv_got_typing_stopped          serv_got_typing_stopped
#define purple_serv_join_chat                   serv_join_chat

#define purple_conversations_find_chat(c, i) \
    purple_conversation_get_chat_data( \
        purple_find_chat(c, i) \
    )

#define purple_conversations_find_chat_with_account(n, a) \
    purple_conversation_get_chat_data( \
        purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, n, a) \
    )

#define purple_notify_error(h, t, p, s, c) \
    purple_notify_message(h, PURPLE_NOTIFY_MSG_ERROR, t, p, s, NULL, NULL)

#define purple_request_fields(h, t, p, s, f, ot, oc, ct, cc, c, d) \
    purple_request_fields(h, t, p, s, f, ot, oc, ct, cc, NULL, NULL, NULL, d)

#define purple_serv_got_joined_chat(c, i, n) \
    purple_conversation_get_chat_data( \
        serv_got_joined_chat(c, i, n) \
    )

#endif /* _PURPLE_COMPAT_H_ */
