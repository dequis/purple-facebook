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

#ifndef _FACEBOOK_MQTT_H_
#define _FACEBOOK_MQTT_H_

/**
 * SECTION:mqtt
 * @section_id: facebook-mqtt
 * @short_description: <filename>mqtt.h</filename>
 * @title: MQTT Connection
 *
 * The MQTT connection.
 */

#include <glib.h>
#include <string.h>

#include "connection.h"

#define FB_TYPE_MQTT  (fb_mqtt_get_type())
#define FB_MQTT(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT, FbMqtt))
#define FB_MQTT_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_MQTT, FbMqttClass))
#define FB_IS_MQTT(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_MQTT))
#define FB_IS_MQTT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_MQTT))
#define FB_MQTT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_MQTT, FbMqttClass))

#define FB_TYPE_MQTT_MESSAGE  (fb_mqtt_message_get_type())
#define FB_MQTT_MESSAGE(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT_MESSAGE, FbMqttMessage))
#define FB_MQTT_MESSAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_MQTT_MESSAGE, FbMqttMessageClass))
#define FB_IS_MQTT_MESSAGE(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_MQTT_MESSAGE))
#define FB_IS_MQTT_MESSAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_MQTT_MESSAGE))
#define FB_MQTT_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_MQTT_MESSAGE, FbMqttMessageClass))

/**
 * FB_MQTT_NAME:
 *
 * The name of the MQTT version.
 */
#define FB_MQTT_NAME  "MQTToT"

/**
 * FB_MQTT_LEVEL:
 *
 * The level of the MQTT version.
 */
#define FB_MQTT_LEVEL  3

/**
 * FB_MQTT_KA:
 *
 * The keep-alive timeout, in seconds, of the MQTT connection.
 */
#define FB_MQTT_KA  60

/**
 * FB_MQTT_HOST:
 *
 * The MQTT host name for Facebook.
 */
#define FB_MQTT_HOST  "mqtt.facebook.com"

/**
 * FB_MQTT_PORT:
 *
 * The MQTT host port for Facebook.
 */
#define FB_MQTT_PORT  443

/**
 * FB_MQTT_TIMEOUT_CONN:
 *
 * The timeout, in milliseconds, to wait for a PING back from the
 * server.
 */
#define FB_MQTT_TIMEOUT_CONN  (FB_MQTT_KA * 1500)

/**
 * FB_MQTT_TIMEOUT_PING:
 *
 * The timeout, in milliseconds, to send a PING to the server.
 */
#define FB_MQTT_TIMEOUT_PING  (FB_MQTT_KA * 1000)

/**
 * FB_MQTT_ERROR:
 *
 * The #GQuark of the domain of MQTT errors.
 */
#define FB_MQTT_ERROR  fb_mqtt_error_quark()

/**
 * FB_MQTT_SSL_ERROR:
 *
 * The #GQuark of the domain of MQTT SSL errors.
 */
#define FB_MQTT_SSL_ERROR  fb_mqtt_ssl_error_quark()

typedef struct _FbMqtt FbMqtt;
typedef struct _FbMqttClass FbMqttClass;
typedef struct _FbMqttPrivate FbMqttPrivate;
typedef struct _FbMqttMessage FbMqttMessage;
typedef struct _FbMqttMessageClass FbMqttMessageClass;
typedef struct _FbMqttMessagePrivate FbMqttMessagePrivate;

/**
 * FbMqttConnectFlags:
 * @FB_MQTT_CONNECT_FLAG_CLR: Clear the session.
 * @FB_MQTT_CONNECT_FLAG_WILL: A will message is in the payload.
 * @FB_MQTT_CONNECT_FLAG_RET: Retain the will message.
 * @FB_MQTT_CONNECT_FLAG_PASS: A password is in the payload.
 * @FB_MQTT_CONNECT_FLAG_USER: A user name is in the payload.
 * @FB_MQTT_CONNECT_FLAG_QOS0: Use no quality of service.
 * @FB_MQTT_CONNECT_FLAG_QOS1: Use level one quality of service.
 * @FB_MQTT_CONNECT_FLAG_QOS2: Use level two quality of service.
 *
 * The #FbMqttMessage flags for the CONNECT message.
 */
typedef enum
{
	FB_MQTT_CONNECT_FLAG_CLR = 1 << 1,
	FB_MQTT_CONNECT_FLAG_WILL = 1 << 2,
	FB_MQTT_CONNECT_FLAG_RET = 1 << 5,
	FB_MQTT_CONNECT_FLAG_PASS = 1 << 6,
	FB_MQTT_CONNECT_FLAG_USER = 1 << 7,
	FB_MQTT_CONNECT_FLAG_QOS0 = 0 << 3,
	FB_MQTT_CONNECT_FLAG_QOS1 = 1 << 3,
	FB_MQTT_CONNECT_FLAG_QOS2 = 2 << 3
} FbMqttConnectFlags;

/**
 * FbMqttError:
 * @FB_MQTT_ERROR_SUCCESS: There is no error.
 * @FB_MQTT_ERROR_PRTVERS: Unacceptable protocol version.
 * @FB_MQTT_ERROR_IDREJECT: Identifier rejected.
 * @FB_MQTT_ERROR_SRVGONE: Server unavailable.
 * @FB_MQTT_ERROR_USERPASS: Bad user name or password.
 * @FB_MQTT_ERROR_UNAUTHORIZED: Not authorized.
 * @FB_MQTT_ERROR_GENERAL: General failure.
 *
 * The error codes for the #FB_MQTT_ERROR domain.
 */
typedef enum
{
	FB_MQTT_ERROR_SUCCESS = 0,
	FB_MQTT_ERROR_PRTVERS = 1,
	FB_MQTT_ERROR_IDREJECT = 2,
	FB_MQTT_ERROR_SRVGONE = 3,
	FB_MQTT_ERROR_USERPASS = 4,
	FB_MQTT_ERROR_UNAUTHORIZED = 5,
	FB_MQTT_ERROR_GENERAL
} FbMqttError;

/**
 * FbMqttMessageFlags:
 * @FB_MQTT_MESSAGE_FLAG_RET: Retain messages.
 * @FB_MQTT_MESSAGE_FLAG_DUP: Duplicate delivery of control packet.
 * @FB_MQTT_MESSAGE_FLAG_QOS0: Use no quality of service.
 * @FB_MQTT_MESSAGE_FLAG_QOS1: Use level one quality of service.
 * @FB_MQTT_MESSAGE_FLAG_QOS2: Use level two quality of service.
 *
 * The #FbMqttMessage flags.
 */
typedef enum
{
	FB_MQTT_MESSAGE_FLAG_RET = 1 << 0,
	FB_MQTT_MESSAGE_FLAG_DUP = 1 << 3,
	FB_MQTT_MESSAGE_FLAG_QOS0 = 0 << 1,
	FB_MQTT_MESSAGE_FLAG_QOS1 = 1 << 1,
	FB_MQTT_MESSAGE_FLAG_QOS2 = 2 << 1
} FbMqttMessageFlags;

/**
 * FbMqttMessageType:
 * @FB_MQTT_MESSAGE_TYPE_CONNECT: Requests a connection.
 * @FB_MQTT_MESSAGE_TYPE_CONNACK: Connection acknowledgment.
 * @FB_MQTT_MESSAGE_TYPE_PUBLISH: Requests a message publication.
 * @FB_MQTT_MESSAGE_TYPE_PUBACK: Publication acknowledgment.
 * @FB_MQTT_MESSAGE_TYPE_PUBREC: Publication received.
 * @FB_MQTT_MESSAGE_TYPE_PUBREL: Publication released.
 * @FB_MQTT_MESSAGE_TYPE_PUBCOMP: Publication complete.
 * @FB_MQTT_MESSAGE_TYPE_SUBSCRIBE: Requests a subscription.
 * @FB_MQTT_MESSAGE_TYPE_SUBACK: Subscription acknowledgment.
 * @FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE: Requests an unsubscription.
 * @FB_MQTT_MESSAGE_TYPE_UNSUBACK: Unsubscription acknowledgment.
 * @FB_MQTT_MESSAGE_TYPE_PINGREQ: Requests a ping response.
 * @FB_MQTT_MESSAGE_TYPE_PINGRESP: Ping response.
 * @FB_MQTT_MESSAGE_TYPE_DISCONNECT: Requests a disconnection.
 *
 * The #FbMqttMessage types.
 */
typedef enum
{
	FB_MQTT_MESSAGE_TYPE_CONNECT = 1,
	FB_MQTT_MESSAGE_TYPE_CONNACK = 2,
	FB_MQTT_MESSAGE_TYPE_PUBLISH = 3,
	FB_MQTT_MESSAGE_TYPE_PUBACK = 4,
	FB_MQTT_MESSAGE_TYPE_PUBREC = 5,
	FB_MQTT_MESSAGE_TYPE_PUBREL = 6,
	FB_MQTT_MESSAGE_TYPE_PUBCOMP = 7,
	FB_MQTT_MESSAGE_TYPE_SUBSCRIBE = 8,
	FB_MQTT_MESSAGE_TYPE_SUBACK = 9,
	FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE = 10,
	FB_MQTT_MESSAGE_TYPE_UNSUBACK = 11,
	FB_MQTT_MESSAGE_TYPE_PINGREQ = 12,
	FB_MQTT_MESSAGE_TYPE_PINGRESP = 13,
	FB_MQTT_MESSAGE_TYPE_DISCONNECT = 14
} FbMqttMessageType;

/**
 * FbMqtt:
 *
 * Represents an MQTT connection.
 */
struct _FbMqtt
{
	/*< private >*/
	GObject parent;
	FbMqttPrivate *priv;
};

/**
 * FbMqttClass:
 *
 * The base class for all #FbMqtt's.
 */
struct _FbMqttClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * FbMqttMessage:
 *
 * Represents a reader/writer for an MQTT message.
 */
struct _FbMqttMessage
{
	/*< private >*/
	GObject parent;
	FbMqttMessagePrivate *priv;
};

/**
 * FbMqttMessageClass:
 *
 * The base class for all #FbMqttMessageClass's.
 */
struct _FbMqttMessageClass
{
	/*< private >*/
	GObjectClass parent_class;
};

/**
 * fb_mqtt_get_type:
 *
 * Returns: The #GType for an #FbMqtt.
 */
GType
fb_mqtt_get_type(void);

/**
 * fb_mqtt_message_get_type:
 *
 * Returns: The #GType for an #FbMqttMessage.
 */
GType
fb_mqtt_message_get_type(void);

/**
 * fb_mqtt_error_quark:
 *
 * Gets the #GQuark of the domain of MQTT errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_mqtt_error_quark(void);

/**
 * fb_mqtt_ssl_error_quark:
 *
 * Gets the #GQuark of the domain of MQTT SSL errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_mqtt_ssl_error_quark(void);

/**
 * fb_mqtt_new:
 * @gc: The #PurpleConnection.
 *
 * Creates a new #FbMqtt. The returned #FbMqtt should be freed with
 * #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbMqtt.
 */
FbMqtt *
fb_mqtt_new(PurpleConnection *gc);

/**
 * fb_mqtt_close:
 * @mqtt: The #FbMqtt.
 *
 * Closes the MQTT without sending the `DISCONNECT` message. The #FbMqtt
 * may be reopened after calling this.
 */
void
fb_mqtt_close(FbMqtt *mqtt);

/**
 * fb_mqtt_error:
 * @mqtt: The #FbMqtt.
 * @error: The #FbMqttError.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Emits an #FbMqttError and closes the #FbMqtt.
 */
void
fb_mqtt_error(FbMqtt *mqtt, FbMqttError error, const gchar *format, ...)
              G_GNUC_PRINTF(3, 4);

/**
 * fb_mqtt_read:
 * @mqtt: The #FbMqtt.
 * @msg: The #FbMqttMessage.
 *
 * Reads an #FbMqttMessage into the #FbMqtt for processing.
 */
void
fb_mqtt_read(FbMqtt *mqtt, FbMqttMessage *msg);

/**
 * fb_mqtt_write:
 * @mqtt: The #FbMqtt.
 * @msg: The #FbMqttMessage.
 *
 * Writes an #FbMqttMessage to the wire.
 */
void
fb_mqtt_write(FbMqtt *mqtt, FbMqttMessage *msg);

/**
 * fb_mqtt_open:
 * @mqtt: The #FbMqtt.
 * @host: The host name.
 * @port: The port.
 *
 * Opens an SSL connection to the remote server.
 */
void
fb_mqtt_open(FbMqtt *mqtt, const gchar *host, gint port);

/**
 * fb_mqtt_connect:
 * @mqtt: The #FbMqtt.
 * @flags: The #FbMqttConnectFlags.
 * @pload: The payload.
 *
 * Sends a message of type #FB_MQTT_MESSAGE_TYPE_CONNECT.
 */
void
fb_mqtt_connect(FbMqtt *mqtt, guint8 flags, const GByteArray *pload);

/**
 * fb_mqtt_connected:
 * @mqtt: The #FbMqtt.
 * @error: #TRUE to error with no connection, otherwise #FALSE.
 *
 * Determines the connection state of the #FbMqtt, and optionally emits
 * an error.
 *
 * Returns: #TRUE if the #FbMqtt is connected, otherwise #FALSE.
 */
gboolean
fb_mqtt_connected(FbMqtt *mqtt, gboolean error);

/**
 * fb_mqtt_disconnect:
 * @mqtt: The #FbMqtt.
 *
 * Sends a message of type #FB_MQTT_MESSAGE_TYPE_DISCONNECT, and closes
 * the connection.
 */
void
fb_mqtt_disconnect(FbMqtt *mqtt);

/**
 * fb_mqtt_publish:
 * @mqtt: The #FbMqtt.
 * @topic: The topic.
 * @pload: The payload.
 *
 * Sends a message of type #FB_MQTT_MESSAGE_TYPE_PUBLISH.
 */
void
fb_mqtt_publish(FbMqtt *mqtt, const gchar *topic, const GByteArray *pload);

/**
 * fb_mqtt_subscribe:
 * @mqtt: The #FbMqtt.
 * @topic1: The first topic.
 * @qos1: The first QoS.
 * @...: The %NULL-terminated list of topic/QoS pairs.
 *
 * Sends a message of type #FB_MQTT_MESSAGE_TYPE_SUBSCRIBE.
 */
void
fb_mqtt_subscribe(FbMqtt *mqtt, const gchar *topic1, guint16 qos1, ...)
                  G_GNUC_NULL_TERMINATED;

/**
 * fb_mqtt_unsubscribe:
 * @mqtt: The #FbMqtt.
 * @topic1: The first topic.
 * @...: The %NULL-terminated list of topics.
 *
 * Sends a message of type #FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE.
 */
void
fb_mqtt_unsubscribe(FbMqtt *mqtt, const gchar *topic1, ...)
                    G_GNUC_NULL_TERMINATED;

/**
 * fb_mqtt_message_new:
 * @type: The #FbMqttMessageType.
 * @flags: The #FbMqttMessageFlags.
 *
 * Creates a new #FbMqttMessage. The returned #FbMqttMessage should be
 * freed with #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbMqttMessage.
 */
FbMqttMessage *
fb_mqtt_message_new(FbMqttMessageType type, FbMqttMessageFlags flags);

/**
 * fb_mqtt_message_new_bytes:
 * @bytes: The #GByteArray.
 *
 * Creates a new #FbMqttMessage from a #GByteArray. The returned
 * #FbMqttMessage should be freed with #g_object_unref() when no
 * longer needed.
 *
 * Returns: The new #FbMqttMessage.
 */
FbMqttMessage *
fb_mqtt_message_new_bytes(GByteArray *bytes);

/**
 * fb_mqtt_message_reset:
 * @msg: The #FbMqttMessage.
 *
 * Resets an #FbMqttMessage. This resets the cursor position, and
 * removes any sort of fixed header.
 */
void
fb_mqtt_message_reset(FbMqttMessage *msg);

/**
 * fb_mqtt_message_bytes:
 * @msg: The #FbMqttMessage.
 *
 * Formats the internal #GByteArray of the #FbMqttMessage with the
 * required fixed header. This resets the cursor position.
 *
 * Returns: The internal #GByteArray.
 */
const GByteArray *
fb_mqtt_message_bytes(FbMqttMessage *msg);

/**
 * fb_mqtt_message_read:
 * @msg: The #FbMqttMessage.
 * @data: The data buffer.
 * @size: The size of @buffer.
 *
 * Reads data from the #FbMqttMessage into a buffer. If @data is #NULL,
 * this will simply advance the cursor position.
 *
 * Returns: #TRUE if the data was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read(FbMqttMessage *msg, gpointer data, guint size);

/**
 * fb_mqtt_message_read_r:
 * @msg: The #FbMqttMessage.
 * @bytes: The #GByteArray.
 *
 * Reads the remaining data from the #FbMqttMessage into a #GByteArray.
 * This is useful for obtaining the payload of a message.
 *
 * Returns: #TRUE if the data was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read_r(FbMqttMessage *msg, GByteArray *bytes);

/**
 * fb_mqtt_message_read_byte:
 * @msg: The #FbMqttMessage.
 * @value: The return location for the value or #NULL.
 *
 * Reads an 8-bit integer value from the #FbMqttMessage. If @value is
 * #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read_byte(FbMqttMessage *msg, guint8 *value);

/**
 * fb_mqtt_message_read_mid:
 * @msg: The #FbMqttMessage.
 * @value: The return location for the value or #NULL.
 *
 * Reads a message identifier from the #FbMqttMessage. If @value is
 * #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read_mid(FbMqttMessage *msg, guint16 *value);

/**
 * fb_mqtt_message_read_u16:
 * @msg: The #FbMqttMessage.
 * @value: The return location for the value or #NULL.
 *
 * Reads a 16-bit integer value from the #FbMqttMessage. If @value is
 * #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read_u16(FbMqttMessage *msg, guint16 *value);

/**
 * fb_mqtt_message_read_str:
 * @msg: The #FbMqttMessage.
 * @value: The return location for the value or #NULL.
 *
 * Reads a string value from the #FbMqttMessage. The value returned to
 * @value should be freed with #g_free() when no longer needed. If
 * @value is #NULL, this will simply advance the cursor position.
 *
 * Returns: #TRUE if the value was read, otherwise #FALSE.
 */
gboolean
fb_mqtt_message_read_str(FbMqttMessage *msg, gchar **value);

/**
 * fb_mqtt_message_write:
 * @msg: The #FbMqttMessage.
 * @data: The data buffer.
 * @size: The size of @buffer.
 *
 * Writes data to the #FbMqttMessage.
 */
void
fb_mqtt_message_write(FbMqttMessage *msg, gconstpointer data, guint size);

/**
 * fb_mqtt_message_write_byte:
 * @msg: The #FbMqttMessage.
 * @value: The value.
 *
 * Writes an 8-bit integer value to the #FbMqttMessage.
 */
void
fb_mqtt_message_write_byte(FbMqttMessage *msg, guint8 value);

/**
 * fb_mqtt_message_write_mid:
 * @msg: The #FbMqttMessage.
 * @value: The value.
 *
 * Writes a message identifier to the #FbMqttMessage. This increments
 * @value for the next message.
 */
void
fb_mqtt_message_write_mid(FbMqttMessage *msg, guint16 *value);

/**
 * fb_mqtt_message_write_u16:
 * @msg: The #FbMqttMessage.
 * @value: The value.
 *
 * Writes a 16-bit integer value to the #FbMqttMessage.
 */
void
fb_mqtt_message_write_u16(FbMqttMessage *msg, guint16 value);

/**
 * fb_mqtt_message_write_str:
 * @msg: The #FbMqttMessage.
 * @value: The value.
 *
 * Writes a string value to the #FbMqttMessage.
 */
void
fb_mqtt_message_write_str(FbMqttMessage *msg, const gchar *value);

#endif /* _FACEBOOK_MQTT_H_ */
