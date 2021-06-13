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

/**
 * SECTION:api
 * @section_id: facebook-api
 * @short_description: <filename>api.h</filename>
 * @title: Facebook API
 *
 * The API for interacting with the Facebook Messenger protocol.
 */

#include "internal.h"

#include <glib.h>

#include "connection.h"

#include "http.h"
#include "id.h"
#include "mqtt.h"

#define FB_TYPE_API  (fb_api_get_type())
#define FB_API(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_API, FbApi))
#define FB_API_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_API, FbApiClass))
#define FB_IS_API(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_API))
#define FB_IS_API_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_API))
#define FB_API_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_API, FbApiClass))

/**
 * FB_API_AHOST:
 *
 * The HTTP host for the Facebook API.
 */
#define FB_API_AHOST  "https://api.facebook.com"

/**
 * FB_API_BHOST:
 *
 * The HTTP host for the Facebook BAPI.
 */
#define FB_API_BHOST  "https://b-api.facebook.com"

/**
 * FB_API_GHOST:
 *
 * The HTTP host for the Facebook Graph API.
 */
#define FB_API_GHOST  "https://graph.facebook.com"

/**
 * FB_API_WHOST:
 *
 * The HTTP host for the Facebook website.
 */
#define FB_API_WHOST  "https://www.facebook.com"

/**
 * FB_API_FBRPC_PREFIX
 *
 * The fbrpc URL prefix used in links shared from the mobile app.
 */
#define FB_API_FBRPC_PREFIX "fbrpc://facebook/nativethirdparty"

/**
 * FB_API_KEY:
 *
 * The Facebook API key.
 */
#define FB_API_KEY  "256002347743983"

/**
 * FB_API_SECRET:
 *
 * The Facebook API secret.
 */
#define FB_API_SECRET  "374e60f8b9bb6b8cbb30f78030438895"

/**
 * FB_ORCA_AGENT
 *
 * The part of the user agent that looks like the official client, since the
 * server started checking this.
 */

#define FB_ORCA_AGENT "[FBAN/Orca-Android;FBAV/537.0.0.31.101;FBPN/com.facebook.orca;FBLC/en_US;FBBV/52182662]"

/**
 * FB_API_AGENT:
 *
 * The HTTP User-Agent header.
 */
#define FB_API_AGENT  "Facebook plugin / Purple / " PACKAGE_VERSION " " FB_ORCA_AGENT

/**
 * FB_API_MQTT_AGENT
 *
 * The client information string sent in the MQTT CONNECT message
 */

#define FB_API_MQTT_AGENT FB_API_AGENT

/**
 * FB_API_URL_ATTACH:
 *
 * The URL for attachment URL requests.
 */
#define FB_API_URL_ATTACH  FB_API_AHOST "/method/messaging.getAttachment"
//#define FB_API_URL_ATTACH  FB_API_AHOST "/method/messaging.attachmentRedirect"

/**
 * FB_API_URL_AUTH:
 *
 * The URL for authentication requests.
 */
#define FB_API_URL_AUTH  FB_API_BHOST "/method/auth.login"

/**
 * FB_API_URL_GQL:
 *
 * The URL for GraphQL requests.
 */
#define FB_API_URL_GQL  FB_API_GHOST "/graphql"

/**
 * FB_API_URL_MESSAGES:
 *
 * The URL for linking message threads.
 */
#define FB_API_URL_MESSAGES  FB_API_WHOST "/messages"

/**
 * FB_API_URL_PARTS:
 *
 * The URL for participant management requests.
 */
#define FB_API_URL_PARTS  FB_API_GHOST "/participants"

/**
 * FB_API_URL_THREADS:
 *
 * The URL for thread management requests.
 */
#define FB_API_URL_THREADS  FB_API_GHOST "/me/group_threads"

/**
 * FB_API_URL_TOPIC:
 *
 * The URL for thread topic requests.
 */
#define FB_API_URL_TOPIC  FB_API_AHOST "/method/messaging.setthreadname"

/**
 * FB_API_QUERY_CONTACT:
 *
 * The query hash for the `UsersQuery`.
 *
 * Key mapping:
 *   0: user_fbids
 *   1: include_full_user_info
 *   2: profile_pic_large_size
 *   3: profile_pic_medium_size
 *   4: profile_pic_small_size
 */
#define FB_API_QUERY_CONTACT  10153915107411729

/**
 * FB_API_QUERY_CONTACTS:
 *
 * The query hash for the `FetchContactsFullQuery`.
 *
 * Key mapping:
 *   0: profile_types
 *   1: limit
 *   2: big_img_size
 *   3: huge_img_size
 *   4: small_img_size
 */
#define FB_API_QUERY_CONTACTS  10154444360806729

/**
 * FB_API_QUERY_CONTACTS_AFTER:
 *
 * The query hash for the `FetchContactsFullWithAfterQuery`.
 *
 * Key mapping:
 *   0: profile_types
 *   1: after
 *   2: limit
 *   3: big_img_size
 *   4: huge_img_size
 *   5: small_img_size
 */
#define FB_API_QUERY_CONTACTS_AFTER  10154444360816729


/**
 * FB_API_QUERY_CONTACTS_DELTA:
 *
 * The query hash for the `FetchContactsDeltaQuery`.
 *
 * Key mapping:
 *   0: after
 *   1: profile_types
 *   2: limit
 *   3: big_img_size
 *   4: huge_img_size
 *   5: small_img_size
 */
#define FB_API_QUERY_CONTACTS_DELTA  10154444360801729

/**
 * FB_API_QUERY_STICKER:
 *
 * The query hash for the `FetchStickersWithPreviewsQuery`.
 *
 * Key mapping:
 *   0: sticker_ids
 *   1: media_type
 *   2: preview_size
 *   3: scaling_factor
 *   4: animated_media_type
 */
#define FB_API_QUERY_STICKER  10152877994321729

/**
 * FB_API_QUERY_THREAD:
 *
 * The query hash for the `ThreadQuery`.
 *
 * Key mapping:
 *   0: thread_ids
 *   1: verification_type
 *   2: hash_key
 *   3: small_preview_size
 *   4: large_preview_size
 *   5: item_count
 *   6: event_count
 *   7: full_screen_height
 *   8: full_screen_width
 *   9: medium_preview_size
 *   10: fetch_users_separately
 *   11: include_message_info
 *   12: msg_count
 *   13: include_full_user_info
 *   14: profile_pic_large_size
 *   15: profile_pic_medium_size
 *   16: profile_pic_small_size
 */
#define FB_API_QUERY_THREAD  10153919752036729

/**
 * FB_API_QUERY_THREADS:
 *
 * The query hash for the `ThreadListQuery`.
 *
 * Key mapping:
 *   0: folder_tag
 *   1: thread_count
 *   2: include_thread_info
 *   3: verification_type
 *   4: hash_key
 *   5: small_preview_size
 *   6: large_preview_size
 *   7: item_count
 *   8: event_count
 *   9: full_screen_height
 *   10: full_screen_width
 *   11: medium_preview_size
 *   12: fetch_users_separately
 *   13: include_message_info
 *   14: msg_count
 *   15: UNKNOWN
 *   16: profile_pic_large_size
 *   17: profile_pic_medium_size
 *   18: profile_pic_small_size
 */
#define FB_API_QUERY_THREADS  10153919752026729

/**
 * FB_API_QUERY_SEQ_ID:
 *
 * A variant of ThreadListQuery with sequence ID
 *
 * TODO: parameters.
 */

#define FB_API_QUERY_SEQ_ID  10155268192741729

/**
 * FB_API_QUERY_XMA:
 *
 * The query hash for the `XMAQuery`.
 *
 * Key mapping:
 *   0: xma_id
 */
#define FB_API_QUERY_XMA  10153919431161729

/**
 * FB_API_CONTACTS_COUNT:
 *
 * The maximum amount of contacts to fetch in a single request. If this
 * value is set too high, HTTP request will fail. This is due to the
 * request data being too large.
 */
#define FB_API_CONTACTS_COUNT  500

/**
 * FB_API_TCHK:
 * @e: The expression.
 *
 * Checks the Thrift related expression to ensure that it evaluates to
 * #TRUE. If the expression evaluates to #FALSE, a #GError is assigned
 * to the local `error` variable, then returns with no value.
 *
 * This macro is meant to only be used for Thrift related expressions,
 * where the calling function has a `void` return type. This macro also
 * requires the existence of a predefined `error` variable, which is a
 * pointer of a pointer to a #GError.
 */
#define FB_API_TCHK(e) \
	G_STMT_START { \
		if (G_UNLIKELY(!(e))) { \
			g_set_error(error, FB_API_ERROR, FB_API_ERROR_GENERAL, \
						"Failed to read thrift: %s:%d " \
						"%s: assertion '%s' failed", \
						__FILE__, __LINE__, G_STRFUNC, #e); \
			return; \
		} \
	} G_STMT_END

/**
 * FB_API_MSGID:
 * @m: The time in milliseconds.
 * @i: The random integer.
 *
 * Creates a 64-bit message identifier in the Facebook format.
 *
 * Returns: The message identifier.
 */
#define FB_API_MSGID(m, i) ((guint64) ( \
		(((guint32) i) & 0x3FFFFF) | \
		(((guint64) m) << 22) \
	))

/**
 * FB_API_ERROR_EMIT:
 * @a: The #FbApi.
 * @e: The #FbApiError.
 * @c: The code to execute.
 *
 * Emits a #GError on behalf of the #FbApi.
 */
#define FB_API_ERROR_EMIT(a, e, c) \
	G_STMT_START { \
		if (G_UNLIKELY((e) != NULL)) { \
			fb_api_error_emit(a, e); \
			{c;} \
		} \
	} G_STMT_END

/**
 * FB_API_ERROR:
 *
 * The #GQuark of the domain of API errors.
 */
#define FB_API_ERROR  fb_api_error_quark()

typedef struct _FbApi FbApi;
typedef struct _FbApiClass FbApiClass;
typedef struct _FbApiPrivate FbApiPrivate;
typedef struct _FbApiEvent FbApiEvent;
typedef struct _FbApiMessage FbApiMessage;
typedef struct _FbApiPresence FbApiPresence;
typedef struct _FbApiThread FbApiThread;
typedef struct _FbApiTyping FbApiTyping;
typedef struct _FbApiUser FbApiUser;

/**
 * FbApiError:
 * @FB_API_ERROR_GENERAL: General failure.
 * @FB_API_ERROR_AUTH: Authentication failure.
 * @FB_API_ERROR_QUEUE: Queue failure.
 * @FB_API_ERROR_NONFATAL: Other non-fatal errors.
 *
 * The error codes for the #FB_API_ERROR domain.
 */
typedef enum
{
	FB_API_ERROR_GENERAL,
	FB_API_ERROR_AUTH,
	FB_API_ERROR_QUEUE,
	FB_API_ERROR_NONFATAL
} FbApiError;

/**
 * FbApiEventType:
 * @FB_API_EVENT_TYPE_THREAD_TOPIC: The thread topic was changed.
 * @FB_API_EVENT_TYPE_THREAD_USER_ADDED: A thread user was added.
 * @FB_API_EVENT_TYPE_THREAD_USER_REMOVED: A thread user was removed.
 *
 * The #FbApiEvent types.
 */
typedef enum
{
	FB_API_EVENT_TYPE_THREAD_TOPIC,
	FB_API_EVENT_TYPE_THREAD_USER_ADDED,
	FB_API_EVENT_TYPE_THREAD_USER_REMOVED
} FbApiEventType;

/**
 * FbApiMessageFlags:
 * @FB_API_MESSAGE_FLAG_DONE: The text has been processed.
 * @FB_API_MESSAGE_FLAG_IMAGE: The text is a URL to an image.
 * @FB_API_MESSAGE_FLAG_SELF: The text is from the #FbApi user.
 *
 * The #FbApiMessage flags.
 */
typedef enum
{
	FB_API_MESSAGE_FLAG_DONE = 1 << 0,
	FB_API_MESSAGE_FLAG_IMAGE = 1 << 1,
	FB_API_MESSAGE_FLAG_SELF = 1 << 2
} FbApiMessageFlags;

/**
 * FbApi:
 *
 * Represents a Facebook Messenger connection.
 */
struct _FbApi
{
	/*< private >*/
	GObject parent;
	FbApiPrivate *priv;
};

/**
 * FbApiClass:
 *
 * The base class for all #FbApi's.
 */
struct _FbApiClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * FbApiEvent:
 * @type: The #FbApiEventType.
 * @uid: The user #FbId.
 * @tid: The thread #FbId.
 * @text: The event text.
 *
 * Represents a Facebook update event.
 */
struct _FbApiEvent
{
	FbApiEventType type;
	FbId uid;
	FbId tid;
	gchar *text;
};

/**
 * FbApiMessage:
 * @flags: The #FbApiMessageFlags.
 * @uid: The user #FbId.
 * @tid: The thread #FbId.
 * @tstamp: The timestamp in milliseconds (UTC).
 * @text: The message text.
 *
 * Represents a Facebook user message.
 */
struct _FbApiMessage
{
	FbApiMessageFlags flags;
	FbId uid;
	FbId tid;
	gint64 tstamp;
	gchar *text;
};

/**
 * FbApiPresence:
 * @uid: The user #FbId.
 * @active: #TRUE if the user is active, otherwise #FALSE.
 *
 * Represents a Facebook presence message.
 */
struct _FbApiPresence
{
	FbId uid;
	gboolean active;
};

/**
 * FbApiThread:
 * @tid: The thread #FbId.
 * @topic: The topic.
 * @users: The #GSList of #FbApiUser's.
 *
 * Represents a Facebook message thread.
 */
struct _FbApiThread
{
	FbId tid;
	gchar *topic;
	GSList *users;
};

/**
 * FbApiTyping:
 * @uid: The user #FbId.
 * @state: #TRUE if the user is typing, otherwise #FALSE.
 *
 * Represents a Facebook typing message.
 */
struct _FbApiTyping
{
	FbId uid;
	gboolean state;
};

/**
 * FbApiUser:
 * @uid: The user #FbId.
 * @name: The name of the user.
 * @icon: The icon URL.
 * @csum: The checksum of @icon.
 *
 * Represents a Facebook user.
 */
struct _FbApiUser
{
	FbId uid;
	gchar *name;
	gchar *icon;
	gchar *csum;
};

/**
 * fb_api_get_type:
 *
 * Returns: The #GType for an #FbApi.
 */
GType
fb_api_get_type(void);

/**
 * fb_api_error_quark:
 *
 * Gets the #GQuark of the domain of API errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_api_error_quark(void);

/**
 * fb_api_new:
 * @gc: The #PurpleConnection.
 *
 * Creates a new #FbApi. The returned #FbApi should be freed with
 * #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbApi.
 */
FbApi *
fb_api_new(PurpleConnection *gc);

/**
 * fb_api_rehash:
 * @api: The #FbApi.
 *
 * Rehashes and updates internal data of the #FbApi. This should be
 * called whenever properties are modified.
 */
void
fb_api_rehash(FbApi *api);

/**
 * fb_api_is_invisible:
 * @api: The #FbApi.
 *
 * Determines if the user of the #FbApi is invisible.
 *
 * Returns: #TRUE if the #FbApi user is invisible, otherwise #FALSE.
 */
gboolean
fb_api_is_invisible(FbApi *api);

/**
 * fb_api_error:
 * @api: The #FbApi.
 * @error: The #FbApiError.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Emits an #FbApiError.
 */
void
fb_api_error(FbApi *api, FbApiError error, const gchar *format, ...)
             G_GNUC_PRINTF(3, 4);

/**
 * fb_api_error_emit:
 * @api: The #FbApi.
 * @error: The #GError.
 *
 * Emits a #GError on an #FbApiError.
 */
void
fb_api_error_emit(FbApi *api, GError *error);

/**
 * fb_api_auth:
 * @api: The #FbApi.
 * @user: The Facebook user name, email, or phone number.
 * @pass: The Facebook password.
 *
 * Sends an authentication request to Facebook. This will obtain
 * session information, which is required for all other requests.
 */
void
fb_api_auth(FbApi *api, const gchar *user, const gchar *pass);

/**
 * fb_api_contact:
 * @api: The #FbApi.
 * @uid: The user #FbId.
 *
 * Sends a contact request. This will obtain the general information of
 * a single contact.
 */
void
fb_api_contact(FbApi *api, FbId uid);

/**
 * fb_api_contacts:
 * @api: The #FbApi.
 *
 * Sends a contacts request. This will obtain a full list of detailed
 * contact information about the friends of the #FbApi user.
 */
void
fb_api_contacts(FbApi *api);

/**
 * fb_api_connect:
 * @api: The #FbApi.
 * @invisible: #TRUE to make the user invisible, otherwise #FALSE.
 *
 * Initializes and establishes the underlying MQTT connection.
 */
void
fb_api_connect(FbApi *api, gboolean invisible);

/**
 * fb_api_disconnect:
 * @api: The #FbApi.
 *
 * Closes the underlying MQTT connection.
 */
void
fb_api_disconnect(FbApi *api);

/**
 * fb_api_message:
 * @api: The #FbApi.
 * @id: The user or thread #FbId.
 * @thread: #TRUE if @id is a thread, otherwise #FALSE.
 * @text: The message text.
 *
 * Sends a message as the user of the #FbApi to a user or a thread.
 */
void
fb_api_message(FbApi *api, FbId id, gboolean thread, const gchar *text);

/**
 * fb_api_publish:
 * @api: The #FbApi.
 * @topic: The topic.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Publishes an MQTT message.
 */
void
fb_api_publish(FbApi *api, const gchar *topic, const gchar *format, ...)
               G_GNUC_PRINTF(3, 4);

/**
 * fb_api_read:
 * @api: The #FbApi.
 * @id: The user or thread #FbId.
 * @thread: #TRUE if @id is a thread, otherwise #FALSE.
 *
 * Marks a message thread as read.
 */
void
fb_api_read(FbApi *api, FbId id, gboolean thread);

/**
 * fb_api_unread:
 * @api: The #FbApi.
 *
 * Sends an unread message request.
 */
void
fb_api_unread(FbApi *api);

/**
 * fb_api_thread:
 * @api: The #FbApi.
 * @tid: The thread #FbId.
 *
 * Sends a thread request. This will obtain the general information of
 * a single thread.
 */
void
fb_api_thread(FbApi *api, FbId tid);

/**
 * fb_api_thread_create:
 * @api: The #FbApi.
 * @uids: The #GSList of #FbId's.
 *
 * Sends a thread creation request. In order to create a thread, there
 * must be at least two other users in @uids.
 */
void
fb_api_thread_create(FbApi *api, GSList *uids);

/**
 * fb_api_thread_invite:
 * @api: The #FbApi.
 * @tid: The thread #FbId.
 * @uid: The user #FbId.
 *
 * Sends a thread user invitation request.
 */
void
fb_api_thread_invite(FbApi *api, FbId tid, FbId uid);

/**
 * fb_api_thread_remove:
 * @api: The #FbApi.
 * @tid: The thread #FbId.
 * @uid: The user #FbId.
 *
 * Sends a thread user removal request.
 */
void
fb_api_thread_remove(FbApi *api, FbId tid, FbId uid);

/**
 * fb_api_thread_topic:
 * @api: The #FbApi.
 * @tid: The thread #FbId.
 * @topic: The topic.
 *
 * Sends a thread topic change request.
 */
void
fb_api_thread_topic(FbApi *api, FbId tid, const gchar *topic);

/**
 * fb_api_threads:
 * @api: The #FbApi.
 *
 * Sends a threads request. This will obtain a full list of detailed
 * thread information about the threads of the #FbApi user.
 */
void
fb_api_threads(FbApi *api);

/**
 * fb_api_typing:
 * @api: The #FbApi.
 * @uid: The user #FbId.
 * @state: #TRUE if the #FbApi user is typing, otherwise #FALSE.
 *
 * Sends a typing state message for the user of the #FbApi.
 */
void
fb_api_typing(FbApi *api, FbId uid, gboolean state);

/**
 * fb_api_event_dup:
 * @event: The #FbApiEvent or #NULL.
 * @deep: #TRUE to duplicate allocated data, otherwise #FALSE.
 *
 * Duplicates an #FbApiEvent. If @event is #NULL, a new zero filled
 * #FbApiEvent is returned. The returned #FbApiEvent should be freed
 * with #fb_api_event_free() when no longer needed.
 *
 * Returns: The new #FbApiEvent.
 */
FbApiEvent *
fb_api_event_dup(const FbApiEvent *event, gboolean deep);

/**
 * fb_api_event_reset:
 * @event: The #FbApiEvent.
 * @deep: #TRUE to free allocated data, otherwise #FALSE.
 *
 * Resets an #FbApiEvent.
 */
void
fb_api_event_reset(FbApiEvent *event, gboolean deep);

/**
 * fb_api_event_free:
 * @event: The #FbApiEvent.
 *
 * Frees all memory used by the #FbApiEvent.
 */
void
fb_api_event_free(FbApiEvent *event);

/**
 * fb_api_message_dup:
 * @msg: The #FbApiMessage or #NULL.
 * @deep: #TRUE to duplicate allocated data, otherwise #FALSE.
 *
 * Duplicates an #FbApiMessage. If @msg is #NULL, a new zero filled
 * #FbApiMessage is returned. The returned #FbApiMessage should be
 * freed with #fb_api_message_free() when no longer needed.
 *
 * Returns: The new #FbApiMessage.
 */
FbApiMessage *
fb_api_message_dup(const FbApiMessage *msg, gboolean deep);

/**
 * fb_api_message_reset:
 * @msg: The #FbApiMessage.
 * @deep: #TRUE to free allocated data, otherwise #FALSE.
 *
 * Resets an #FbApiMessage.
 */
void
fb_api_message_reset(FbApiMessage *msg, gboolean deep);

/**
 * fb_api_message_free:
 * @msg: The #FbApiMessage.
 *
 * Frees all memory used by the #FbApiMessage.
 */
void
fb_api_message_free(FbApiMessage *msg);

/**
 * fb_api_presence_dup:
 * @pres: The #FbApiPresence or #NULL.
 *
 * Duplicates an #FbApiPresence. If @pres is #NULL, a new zero filled
 * #FbApiPresence is returned. The returned #FbApiPresence should be
 * freed with #fb_api_presence_free() when no longer needed.
 *
 * Returns: The new #FbApiPresence.
 */
FbApiPresence *
fb_api_presence_dup(const FbApiPresence *pres);

/**
 * fb_api_presence_reset:
 * @pres: The #FbApiPresence.
 *
 * Resets an #FbApiPresence.
 */
void
fb_api_presence_reset(FbApiPresence *pres);

/**
 * fb_api_presence_free:
 * @pres: The #FbApiPresence.
 *
 * Frees all memory used by the #FbApiPresence.
 */
void
fb_api_presence_free(FbApiPresence *pres);

/**
 * fb_api_thread_dup:
 * @thrd: The #FbApiThread or #NULL.
 * @deep: #TRUE to duplicate allocated data, otherwise #FALSE.
 *
 * Duplicates an #FbApiThread. If @thrd is #NULL, a new zero filled
 * #FbApiThread is returned. The returned #FbApiThread should be freed
 * with #fb_api_thread_free() when no longer needed.
 *
 * Returns: The new #FbApiThread.
 */
FbApiThread *
fb_api_thread_dup(const FbApiThread *thrd, gboolean deep);

/**
 * fb_api_thread_reset:
 * @thrd: The #FbApiThread.
 * @deep: #TRUE to free allocated data, otherwise #FALSE.
 *
 * Resets an #FbApiThread.
 */
void
fb_api_thread_reset(FbApiThread *thrd, gboolean deep);

/**
 * fb_api_thread_free:
 * @thrd: The #FbApiThread.
 *
 * Frees all memory used by the #FbApiThread.
 */
void
fb_api_thread_free(FbApiThread *thrd);

/**
 * fb_api_typing_dup:
 * @typg: The #FbApiTyping or #NULL.
 *
 * Duplicates an #FbApiTyping. If @typg is #NULL, a new zero filled
 * #FbApiTyping is returned. The returned #FbApiTyping should be freed
 * with #fb_api_typing_free() when no longer needed.
 *
 * Returns: The new #FbApiTyping.
 */
FbApiTyping *
fb_api_typing_dup(const FbApiTyping *typg);

/**
 * fb_api_typing_reset:
 * @typg: The #FbApiTyping.
 *
 * Resets an #FbApiTyping.
 */
void
fb_api_typing_reset(FbApiTyping *typg);

/**
 * fb_api_typing_free:
 * @typg: The #FbApiTyping.
 *
 * Frees all memory used by the #FbApiTyping.
 */
void
fb_api_typing_free(FbApiTyping *typg);

/**
 * fb_api_user_dup:
 * @user: The #FbApiUser or #NULL.
 * @deep: #TRUE to duplicate allocated data, otherwise #FALSE.
 *
 * Duplicates an #FbApiUser. If @user is #NULL, a new zero filled
 * #FbApiUser is returned. The returned #FbApiUser should be freed with
 * #fb_api_user_free() when no longer needed.
 *
 * Returns: The new #FbApiUser.
 */
FbApiUser *
fb_api_user_dup(const FbApiUser *user, gboolean deep);

/**
 * fb_api_user_reset:
 * @user: The #FbApiUser.
 * @deep: #TRUE to free allocated data, otherwise #FALSE.
 *
 * Resets an #FbApiUser.
 */
void
fb_api_user_reset(FbApiUser *user, gboolean deep);

/**
 * fb_api_user_free:
 * @user: The #FbApiUser.
 *
 * Frees all memory used by the #FbApiUser.
 */
void
fb_api_user_free(FbApiUser *user);

#endif /* _FACEBOOK_API_H_ */
