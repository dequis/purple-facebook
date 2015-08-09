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

#ifndef _FACEBOOK_API_H_
#define _FACEBOOK_API_H_

#include "internal.h"

#include <glib.h>

#include "connection.h"

#include "http.h"
#include "id.h"
#include "mqtt.h"

#define FB_API_AHOST   "https://api.facebook.com"
#define FB_API_BHOST   "https://b-api.facebook.com"
#define FB_API_GHOST   "https://graph.facebook.com"
#define FB_API_WHOST   "https://www.facebook.com"
#define FB_API_AGENT   "Facebook App / " PACKAGE " / " VERSION
#define FB_API_KEY     "256002347743983"
#define FB_API_SECRET  "374e60f8b9bb6b8cbb30f78030438895"

#define FB_API_CONTACTS_COUNT  "200"

#define FB_API_URL_AUTH     FB_API_BHOST "/method/auth.login"
#define FB_API_URL_GQL      FB_API_GHOST "/graphql"
#define FB_API_URL_MESSAGES FB_API_WHOST "/messages"
#define FB_API_URL_PARTS    FB_API_GHOST "/participants"
#define FB_API_URL_STICKER  FB_API_WHOST "/stickers/asset/"
#define FB_API_URL_THRDS    FB_API_GHOST "/me/threads"
#define FB_API_URL_TOPIC    FB_API_AHOST "/method/messaging.setthreadname"

#define FB_API_QRYID_CONTACTS        "10153856456271729"
#define FB_API_QRYID_CONTACTS_AFTER  "10153856456281729"
#define FB_API_QRYID_THREAD_INFO     "10153919752036729"
#define FB_API_QRYID_THREAD_LIST     "10153919752026729"
#define FB_API_QRYID_XMA             "10153919431161729"

#define FB_TYPE_API             (fb_api_get_type())
#define FB_API(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_API, FbApi))
#define FB_API(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_API, FbApi))
#define FB_API_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_API, FbApiClass))
#define FB_IS_API(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_API))
#define FB_IS_API_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_API))
#define FB_API_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_API, FbApiClass))

#define FB_API_MSGID(m, i) ((guint64) (      \
		(((guint32) i) & 0x3FFFFF) | \
		(((guint64) m) << 22)        \
	))

#define FB_API_ERROR_EMIT(a, e, c)               \
	G_STMT_START {                           \
		if (G_UNLIKELY((e) != NULL)) {   \
			fb_api_error_emit(a, e); \
			{c;}                     \
		}                                \
	} G_STMT_END

#define FB_API_ERROR fb_api_error_quark()

typedef enum _FbApiError FbApiError;
typedef struct _FbApi FbApi;
typedef struct _FbApiClass FbApiClass;
typedef struct _FbApiPrivate FbApiPrivate;
typedef struct _FbApiMessage FbApiMessage;
typedef struct _FbApiPresence FbApiPresence;
typedef struct _FbApiThread FbApiThread;
typedef struct _FbApiTyping FbApiTyping;
typedef struct _FbApiUser FbApiUser;
typedef struct _FbApiHttpInfo FbApiHttpInfo;


enum _FbApiError
{
	FB_API_ERROR_GENERAL,
	FB_API_ERROR_AUTH
};

struct _FbApi
{
	GObject parent;
	FbApiPrivate *priv;
};

struct _FbApiClass
{
	GObjectClass parent_class;
};

struct _FbApiMessage
{
	FbId uid;
	FbId tid;
	gchar *text;
	gboolean isself;
};

struct _FbApiPresence
{
	FbId uid;
	gboolean active;
};

struct _FbApiThread
{
	FbId tid;
	gchar *topic;
	GSList *users;
};

struct _FbApiTyping
{
	FbId uid;
	gboolean state;
};

struct _FbApiUser
{
	FbId uid;
	gchar *name;
	gchar *icon;
	gchar *csum;
};

struct _FbApiHttpInfo
{
	PurpleHttpCallback callback;
	const gchar *klass;
	const gchar *name;
	const gchar *method;
};


GType
fb_api_get_type(void);

GQuark
fb_api_error_quark(void);

FbApi *
fb_api_new(PurpleConnection *gc);

void
fb_api_rehash(FbApi *api);

gboolean
fb_api_is_invisible(FbApi *api);

void
fb_api_error(FbApi *api, FbApiError err, const gchar *fmt, ...)
             G_GNUC_PRINTF(3, 4);

void
fb_api_error_emit(FbApi *api, GError *error);

void
fb_api_auth(FbApi *api, const gchar *user, const gchar *pass);

void
fb_api_contacts(FbApi *api);

void
fb_api_connect(FbApi *api, gboolean invisible);

void
fb_api_disconnect(FbApi *api);

void
fb_api_message(FbApi *api, FbId id, gboolean thread, const gchar *msg);

void
fb_api_publish(FbApi *api, const gchar *topic, const gchar *fmt, ...)
               G_GNUC_PRINTF(3, 4);

void
fb_api_read(FbApi *api, FbId id, gboolean thread);

void
fb_api_unread(FbApi *api);

void
fb_api_thread_create(FbApi *api, GSList *uids);

void
fb_api_thread_info(FbApi *api, FbId tid);

void
fb_api_thread_invite(FbApi *api, FbId tid, FbId uid);

void
fb_api_thread_list(FbApi *api);

void
fb_api_thread_remove(FbApi *api, FbId tid, FbId uid);

void
fb_api_thread_topic(FbApi *api, FbId tid, const gchar *topic);

void
fb_api_typing(FbApi *api, FbId uid, gboolean state);

FbApiMessage *
fb_api_message_new(FbId uid, FbId tid, const gchar *text, gboolean isself);

FbApiMessage *
fb_api_message_dup(FbApiMessage *msg, gboolean deep);

void
fb_api_message_reset(FbApiMessage *msg, gboolean deep);

void
fb_api_message_free(FbApiMessage *msg);

FbApiPresence *
fb_api_presence_new(FbId uid, gboolean active);

FbApiPresence *
fb_api_presence_dup(FbApiPresence *pres);

void
fb_api_presence_reset(FbApiPresence *pres);

void
fb_api_presence_free(FbApiPresence *pres);

FbApiThread *
fb_api_thread_new(FbId tid, const gchar *topic, GSList *users);

FbApiThread *
fb_api_thread_dup(FbApiThread *thrd, gboolean deep);

void
fb_api_thread_reset(FbApiThread *thrd, gboolean deep);

void
fb_api_thread_free(FbApiThread *thrd);

FbApiTyping *
fb_api_typing_new(FbId uid, gboolean state);

FbApiTyping *
fb_api_typing_dup(FbApiTyping *typg);

void
fb_api_typing_reset(FbApiTyping *typg);

void
fb_api_typing_free(FbApiTyping *typg);

FbApiUser *
fb_api_user_new(FbId uid, const gchar *name, const gchar *icon,
                const gchar *csum);

FbApiUser *
fb_api_user_dup(FbApiUser *user, gboolean deep);

void
fb_api_user_reset(FbApiUser *user, gboolean deep);

void
fb_api_user_free(FbApiUser *user);

#endif /* _FACEBOOK_API_H_ */
