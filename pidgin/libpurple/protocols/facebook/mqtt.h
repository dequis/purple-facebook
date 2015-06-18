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

#include <string.h>

#include "glibcompat.h"

#define FB_MQTT_NAME "MQIsdp"
#define FB_MQTT_VERS 3
#define FB_MQTT_KA   60
#define FB_MQTT_HOST "mqtt.facebook.com"
#define FB_MQTT_PORT 443

#define FB_MQTT_TIMEOUT_CONN (FB_MQTT_KA * 1500)
#define FB_MQTT_TIMEOUT_PING (FB_MQTT_KA * 1000)

#define FB_TYPE_MQTT             (fb_mqtt_get_type())
#define FB_MQTT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT, FbMqtt))
#define FB_MQTT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT, FbMqtt))
#define FB_MQTT_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_MQTT, FbMqttClass))
#define FB_IS_MQTT(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_MQTT))
#define FB_IS_MQTT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_MQTT))
#define FB_MQTT_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_MQTT, FbMqttClass))

#define FB_TYPE_MQTT_MESSAGE             (fb_mqtt_message_get_type())
#define FB_MQTT_MESSAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT_MESSAGE, FbMqttMessage))
#define FB_MQTT_MESSAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_MQTT_MESSAGE, FbMqttMessage))
#define FB_MQTT_MESSAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_MQTT_MESSAGE, FbMqttMessageClass))
#define FB_IS_MQTT_MESSAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_MQTT_MESSAGE))
#define FB_IS_MQTT_MESSAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_MQTT_MESSAGE))
#define FB_MQTT_MESSAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_MQTT_MESSAGE, FbMqttMessageClass))

#define FB_MQTT_ERROR  fb_mqtt_error_quark()

typedef enum _FbMqttConnectFlags FbMqttConnectFlags;
typedef enum _FbMqttError FbMqttError;
typedef enum _FbMqttMessageFlags FbMqttMessageFlags;
typedef enum _FbMqttMessageType FbMqttMessageType;
typedef struct _FbMqtt FbMqtt;
typedef struct _FbMqttClass FbMqttClass;
typedef struct _FbMqttPrivate FbMqttPrivate;
typedef struct _FbMqttMessage FbMqttMessage;
typedef struct _FbMqttMessageClass FbMqttMessageClass;
typedef struct _FbMqttMessagePrivate FbMqttMessagePrivate;

enum _FbMqttConnectFlags
{
	FB_MQTT_CONNECT_FLAG_CLR  = 1 << 1,
	FB_MQTT_CONNECT_FLAG_WILL = 1 << 2,
	FB_MQTT_CONNECT_FLAG_RET  = 1 << 5,
	FB_MQTT_CONNECT_FLAG_PASS = 1 << 6,
	FB_MQTT_CONNECT_FLAG_USER = 1 << 7,
	FB_MQTT_CONNECT_FLAG_QOS0 = 0 << 3,
	FB_MQTT_CONNECT_FLAG_QOS1 = 1 << 3,
	FB_MQTT_CONNECT_FLAG_QOS2 = 2 << 3
};

enum _FbMqttError
{
	FB_MQTT_ERROR_SUCCESS      = 0,
	FB_MQTT_ERROR_PRTVERS      = 1,
	FB_MQTT_ERROR_IDREJECT     = 2,
	FB_MQTT_ERROR_SRVGONE      = 3,
	FB_MQTT_ERROR_USERPASS     = 4,
	FB_MQTT_ERROR_UNAUTHORIZED = 5,
	FB_MQTT_ERROR_GENERAL
};

enum _FbMqttMessageFlags
{
	FB_MQTT_MESSAGE_FLAG_RET  = 1 << 0,
	FB_MQTT_MESSAGE_FLAG_DUP  = 1 << 3,
	FB_MQTT_MESSAGE_FLAG_QOS0 = 0 << 1,
	FB_MQTT_MESSAGE_FLAG_QOS1 = 1 << 1,
	FB_MQTT_MESSAGE_FLAG_QOS2 = 2 << 1
};

enum _FbMqttMessageType
{
	FB_MQTT_MESSAGE_TYPE_CONNECT     = 1,
	FB_MQTT_MESSAGE_TYPE_CONNACK     = 2,
	FB_MQTT_MESSAGE_TYPE_PUBLISH     = 3,
	FB_MQTT_MESSAGE_TYPE_PUBACK      = 4,
	FB_MQTT_MESSAGE_TYPE_PUBREC      = 5,
	FB_MQTT_MESSAGE_TYPE_PUBREL      = 6,
	FB_MQTT_MESSAGE_TYPE_PUBCOMP     = 7,
	FB_MQTT_MESSAGE_TYPE_SUBSCRIBE   = 8,
	FB_MQTT_MESSAGE_TYPE_SUBACK      = 9,
	FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE = 10,
	FB_MQTT_MESSAGE_TYPE_UNSUBACK    = 11,
	FB_MQTT_MESSAGE_TYPE_PINGREQ     = 12,
	FB_MQTT_MESSAGE_TYPE_PINGRESP    = 13,
	FB_MQTT_MESSAGE_TYPE_DISCONNECT  = 14
};

struct _FbMqtt
{
	GObject parent;
	FbMqttPrivate *priv;
};

struct _FbMqttClass
{
	GObjectClass parent_class;
};

struct _FbMqttMessage
{
	GObject parent;
	FbMqttMessagePrivate *priv;
};

struct _FbMqttMessageClass
{
	GObjectClass parent_class;
};


GType
fb_mqtt_get_type(void);

GType
fb_mqtt_message_get_type(void);

GQuark
fb_mqtt_error_quark(void);

FbMqtt *
fb_mqtt_new(PurpleConnection *gc);

void
fb_mqtt_close(FbMqtt *mqtt);

void
fb_mqtt_error(FbMqtt *mqtt, FbMqttError error, const gchar *format, ...)
              G_GNUC_PRINTF(3, 4);

void
fb_mqtt_read(FbMqtt *mqtt, FbMqttMessage *msg);

void
fb_mqtt_write(FbMqtt *mqtt, FbMqttMessage *msg);

void
fb_mqtt_open(FbMqtt *mqtt, const gchar *host, gint port);

void
fb_mqtt_connect(FbMqtt *mqtt, guint8 flags, const gchar *cid, ...)
                G_GNUC_NULL_TERMINATED;

gboolean
fb_mqtt_connected(FbMqtt *mqtt, gboolean error);

void
fb_mqtt_disconnect(FbMqtt *mqtt);

void
fb_mqtt_publish(FbMqtt *mqtt, const gchar *topic, const GByteArray *bytes);

void
fb_mqtt_subscribe(FbMqtt *mqtt, const gchar *topic1, guint16 qos1, ...)
                  G_GNUC_NULL_TERMINATED;

void
fb_mqtt_unsubscribe(FbMqtt *mqtt, const gchar *topic1, ...)
                    G_GNUC_NULL_TERMINATED;

FbMqttMessage *
fb_mqtt_message_new(FbMqttMessageType type, FbMqttMessageFlags flags);

FbMqttMessage *
fb_mqtt_message_new_bytes(GByteArray *bytes);

void
fb_mqtt_message_reset(FbMqttMessage *msg);

const GByteArray *
fb_mqtt_message_bytes(FbMqttMessage *msg);

gboolean
fb_mqtt_message_read(FbMqttMessage *msg, gpointer data, guint size);

gboolean
fb_mqtt_message_read_r(FbMqttMessage *msg, GByteArray *bytes);

gboolean
fb_mqtt_message_read_byte(FbMqttMessage *msg, guint8 *byte);

gboolean
fb_mqtt_message_read_mid(FbMqttMessage *msg, guint16 *mid);

gboolean
fb_mqtt_message_read_u16(FbMqttMessage *msg, guint16 *u16);

gboolean
fb_mqtt_message_read_str(FbMqttMessage *msg, gchar **str);

void
fb_mqtt_message_write(FbMqttMessage *msg, gconstpointer data, guint size);

void
fb_mqtt_message_write_byte(FbMqttMessage *msg, guint8 byte);

void
fb_mqtt_message_write_mid(FbMqttMessage *msg, guint16 *mid);

void
fb_mqtt_message_write_u16(FbMqttMessage *msg, guint16 u16);

void
fb_mqtt_message_write_str(FbMqttMessage *msg, const gchar *str);

#endif /* _FACEBOOK_MQTT_H_ */
