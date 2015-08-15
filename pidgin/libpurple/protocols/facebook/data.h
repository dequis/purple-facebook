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

#ifndef _FACEBOOK_DATA_H_
#define _FACEBOOK_DATA_H_

/**
 * SECTION:data
 * @section_id: facebook-data
 * @short_description: <filename>data.h</filename>
 * @title: Connection Data
 *
 * The Connection Data.
 */

#include <glib.h>

#include "blistnodetypes.h"
#include "connection.h"
#include "roomlist.h"

#include "api.h"
#include "http.h"
#include "id.h"

#define FB_TYPE_DATA             (fb_data_get_type())
#define FB_DATA(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_DATA, FbData))
#define FB_DATA(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_DATA, FbData))
#define FB_DATA_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_DATA, FbDataClass))
#define FB_IS_DATA(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_DATA))
#define FB_IS_DATA_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_DATA))
#define FB_DATA_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_DATA, FbDataClass))

/**
 * FB_DATA_ICON_MAX:
 *
 * The maximum of number of concurrent icon fetches.
 */
#define FB_DATA_ICON_MAX  4

typedef struct _FbData FbData;
typedef struct _FbDataClass FbDataClass;
typedef struct _FbDataPrivate FbDataPrivate;
typedef struct _FbDataIcon FbDataIcon;

/**
 * FbData:
 *
 * Represents the connection data used by #FacebookProtocol.
 */
struct _FbData
{
	/*< private >*/
	GObject parent;
	FbDataPrivate *priv;
};

/**
 * FbDataClass:
 *
 * The base class for all #FbData's.
 */
struct _FbDataClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * FbDataIcon:
 * @fata: The #FbData.
 * @buddy: The #PurpleBuddy.
 * @url: The image URL.
 * @func: The #PurpleHttpCallback.
 *
 * Represents the data used for fetching icons.
 */
struct _FbDataIcon
{
	FbData *fata;
	PurpleBuddy *buddy;
	gchar *url;
	PurpleHttpCallback func;
};

/**
 * fb_data_get_type:
 *
 * Returns: The #GType for an #FbData.
 */
GType
fb_data_get_type(void);

/**
 * fb_data_new:
 * @gc: The #PurpleConnection.
 *
 * Creates a new #FbData. The returned #FbData should be freed with
 * #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbData.
 */
FbData *
fb_data_new(PurpleConnection *gc);

/**
 * fb_data_load:
 * @fata: The #FbData.
 *
 * Loads the internal data from the underlying #PurpleAccount.
 *
 * Return: TRUE if all of the data was loaded, otherwise FALSE.
 */
gboolean
fb_data_load(FbData *fata);

/**
 * fb_data_save:
 * @fata: The #FbData.
 *
 * Saves the internal data to the underlying #PurpleAccount.
 */
void
fb_data_save(FbData *fata);

/**
 * fb_data_add_timeout:
 * @fata: The #FbData.
 * @name: The name of the timeout.
 * @interval: The time, in milliseconds, between calls to @func.
 * @func: The #GSourceFunc.
 * @data: The data passed to @func.
 *
 * Adds a new callback timer. The callback is called repeatedly on the
 * basis of @interval, until @func returns #FALSE. The timeout should
 * be cleared with #fb_data_clear_timeout() when no longer needed.
 */
void
fb_data_add_timeout(FbData *fata, const gchar *name, guint interval,
                    GSourceFunc func, gpointer data);

/**
 * fb_data_clear_timeout:
 * @fata: The #FbData.
 * @name: The name of the timeout.
 * @remove: #TRUE to remove from the event loop, otherwise #FALSE.
 *
 * Clears and removes a callback timer. The only time @remove should be
 * #FALSE, is when being called from a #GSourceFunc, which is returning
 * #FALSE.
 */
void
fb_data_clear_timeout(FbData *fata, const gchar *name, gboolean remove);

/**
 * fb_data_get_api:
 * @fata: The #FbData.
 *
 * Gets the #FbApi from the #FbData.
 *
 * Return: The #FbApi.
 */
FbApi *
fb_data_get_api(FbData *fata);

/**
 * fb_data_get_connection:
 * @fata: The #FbData.
 *
 * Gets the #PurpleConnection from the #FbData.
 *
 * Return: The #PurpleConnection.
 */
PurpleConnection *
fb_data_get_connection(FbData *fata);

/**
 * fb_data_get_roomlist:
 * @fata: The #FbData.
 *
 * Gets the #PurpleRoomlist from the #FbData.
 *
 * Return: The #PurpleRoomlist.
 */
PurpleRoomlist *
fb_data_get_roomlist(FbData *fata);

/**
 * fb_data_get_unread:
 * @fata: The #FbData.
 * @id: The #FbId.
 *
 * Gets the unread state of an #FbId.
 *
 * Return: #TRUE if the #FbId is unread, otherwise #FALSE.
 */
gboolean
fb_data_get_unread(FbData *fata, FbId id);

/**
 * fb_data_set_roomlist:
 * @fata: The #FbData.
 * @list: The #PurpleRoomlist.
 *
 * Sets the #PurpleRoomlist to the #FbData.
 */
void
fb_data_set_roomlist(FbData *fata, PurpleRoomlist *list);

/**
 * fb_data_set_unread:
 * @fata: The #FbData.
 * @id: The #FbId.
 * @unread: #TRUE if the #FbId is unread, otherwise FALSE.
 *
 * Sets the unread state of an #FbId to the #FbData.
 */
void
fb_data_set_unread(FbData *fata, FbId id, gboolean unread);

/**
 * fb_data_add_message:
 * @fata: The #FbData.
 * @msg: The #FbApiMessage.
 *
 * Adds an #FbApiMessage to the #FbData.
 */
void
fb_data_add_message(FbData *fata, FbApiMessage *msg);

/**
 * fb_data_take_messages:
 * @fata: The #FbData.
 * @uid: The user #FbId.
 *
 * Gets a #GSList of messages by the user #FbId from the #FbData. The
 * #FbApiMessage's are removed from the #FbData. The returned #GSList
 * and its #FbApiMessage's should be freed with #fb_api_message_free()
 * and #g_slist_free_full() when no longer needed.
 */
GSList *
fb_data_take_messages(FbData *fata, FbId uid);

/**
 * fb_data_icon_add:
 * @fata: The #FbData.
 * @buddy: The @PurpleBuddy.
 * @url: The image URL.
 * @func: The #PurpleHttpCallback.
 *
 * Adds a new #FbDataIcon to the #FbData. This is used to fetch user
 * icons from HTTP sources. After calling this, #fb_data_icon_queue()
 * should be called to queue the fetching process. The returned
 * #FbDataIcon should not be freed.
 *
 * Return: The #FbDataIcon.
 */
FbDataIcon *
fb_data_icon_add(FbData *fata, PurpleBuddy *buddy, const gchar *url,
                 PurpleHttpCallback func);

/**
 * fb_data_icon_destroy:
 * @icon: The #FbDataIcon.
 *
 * Destroys an #FbDataIcon by removing it from the #FbData, and freeing
 * all memory used by it.
 */
void
fb_data_icon_destroy(FbDataIcon *icon);

/**
 * fb_data_icon_queue:
 * @fata: The #FbData.
 *
 * Queues the next #FbDataIcon fetches.
 */
void
fb_data_icon_queue(FbData *fata);

#endif /* _FACEBOOK_DATA_H_ */
