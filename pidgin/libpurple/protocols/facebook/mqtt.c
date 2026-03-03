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

#include <glib/gprintf.h>
#include <stdarg.h>
#include <string.h>

#include "account.h"
#include "eventloop.h"
#include "glibcompat.h"
#include "purple-gio.h"
#include "queuedoutputstream.h"

#include "mqtt.h"
#include "util.h"

struct _FbMqttPrivate
{
	PurpleConnection *gc;
	GIOStream *conn;
	GBufferedInputStream *input;
	PurpleQueuedOutputStream *output;
	GCancellable *cancellable;
	gboolean connected;
	guint16 mid;

	GByteArray *rbuf;
	gsize remz;

	gint tev;
};

struct _FbMqttMessagePrivate
{
	FbMqttMessageType type;
	FbMqttMessageFlags flags;

	GByteArray *bytes;
	guint offset;
	guint pos;

	gboolean local;
};

G_DEFINE_TYPE(FbMqtt, fb_mqtt, G_TYPE_OBJECT);
G_DEFINE_TYPE(FbMqttMessage, fb_mqtt_message, G_TYPE_OBJECT);

static void fb_mqtt_read_packet(FbMqtt *mqtt);

static void
fb_mqtt_dispose(GObject *obj)
{
	FbMqtt *mqtt = FB_MQTT(obj);
	FbMqttPrivate *priv = mqtt->priv;

	fb_mqtt_close(mqtt);
	g_byte_array_free(priv->rbuf, TRUE);
}

static void
fb_mqtt_class_init(FbMqttClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);

	gklass->dispose = fb_mqtt_dispose;
	g_type_class_add_private(klass, sizeof (FbMqttPrivate));

	/**
	 * FbMqtt::connect:
	 * @mqtt: The #FbMqtt.
	 *
	 * Emitted upon the successful completion of the connection
	 * process. This is emitted as a result of #fb_mqtt_connect().
	 */
	g_signal_new("connect",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL, NULL,
	             G_TYPE_NONE,
	             0);

	/**
	 * FbMqtt::error:
	 * @mqtt: The #FbMqtt.
	 * @error: The #GError.
	 *
	 * Emitted whenever an error is hit within the #FbMqtt. This
	 * should close the #FbMqtt with #fb_mqtt_close().
	 */
	g_signal_new("error",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL, NULL,
	             G_TYPE_NONE,
	             1, G_TYPE_ERROR);

	/**
	 * FbMqtt::open:
	 * @mqtt: The #FbMqtt.
	 *
	 * Emitted upon the successful opening of the remote socket.
	 * This is emitted as a result of #fb_mqtt_open(). This should
	 * call #fb_mqtt_connect().
	 */
	g_signal_new("open",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL, NULL,
	             G_TYPE_NONE,
	             0);

	/**
	 * FbMqtt::publish:
	 * @mqtt: The #FbMqtt.
	 * @topic: The topic.
	 * @pload: The payload.
	 *
	 * Emitted upon an incoming message from the steam.
	 */
	g_signal_new("publish",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL, NULL,
	             G_TYPE_NONE,
	             2, G_TYPE_STRING, G_TYPE_BYTE_ARRAY);
}

static void
fb_mqtt_init(FbMqtt *mqtt)
{
	FbMqttPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(mqtt, FB_TYPE_MQTT, FbMqttPrivate);
	mqtt->priv = priv;

	priv->rbuf = g_byte_array_new();
}

static void
fb_mqtt_message_dispose(GObject *obj)
{
	FbMqttMessagePrivate *priv = FB_MQTT_MESSAGE(obj)->priv;

	if ((priv->bytes != NULL) && priv->local) {
		g_byte_array_free(priv->bytes, TRUE);
	}
}

static void
fb_mqtt_message_class_init(FbMqttMessageClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);

	gklass->dispose = fb_mqtt_message_dispose;
	g_type_class_add_private(klass, sizeof (FbMqttMessagePrivate));
}

static void
fb_mqtt_message_init(FbMqttMessage *msg)
{
	FbMqttMessagePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(msg, FB_TYPE_MQTT_MESSAGE,
	                                   FbMqttMessagePrivate);
	msg->priv = priv;
}

GQuark
fb_mqtt_error_quark(void)
{
	static GQuark q = 0;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-mqtt-error-quark");
	}

	return q;
}

FbMqtt *
fb_mqtt_new(PurpleConnection *gc)
{
	FbMqtt *mqtt;
	FbMqttPrivate *priv;

	g_return_val_if_fail(PURPLE_IS_CONNECTION(gc), NULL);

	mqtt = g_object_new(FB_TYPE_MQTT,  NULL);
	priv = mqtt->priv;
	priv->gc = gc;

	return mqtt;
};

void
fb_mqtt_close(FbMqtt *mqtt)
{
	FbMqttPrivate *priv;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	priv = mqtt->priv;

	if (priv->tev > 0) {
		g_source_remove(priv->tev);
		priv->tev = 0;
	}

	if (priv->cancellable != NULL) {
		g_cancellable_cancel(priv->cancellable);
		g_clear_object(&priv->cancellable);
	}

	if (priv->conn != NULL) {
		purple_gio_graceful_close(priv->conn,
				G_INPUT_STREAM(priv->input),
				G_OUTPUT_STREAM(priv->output));
		g_clear_object(&priv->input);
		g_clear_object(&priv->output);
		g_clear_object(&priv->conn);
	}

	priv->connected = FALSE;
	g_byte_array_set_size(priv->rbuf, 0);
}

static void
fb_mqtt_take_error(FbMqtt *mqtt, GError *err, const gchar *prefix)
{
	if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/* Return as cancelled means the connection is closing */
		g_error_free(err);
		return;
	}

	/* Now we can check for programming errors */
	g_return_if_fail(FB_IS_MQTT(mqtt));

	if (prefix != NULL) {
		g_prefix_error(&err, "%s: ", prefix);
	}

	g_signal_emit_by_name(mqtt, "error", err);
	g_error_free(err);
}

void
fb_mqtt_error(FbMqtt *mqtt, FbMqttError error, const gchar *format, ...)
{
	GError *err;
	va_list ap;

	g_return_if_fail(FB_IS_MQTT(mqtt));

	va_start(ap, format);
	err = g_error_new_valist(FB_MQTT_ERROR, error, format, ap);
	va_end(ap);

	g_signal_emit_by_name(mqtt, "error", err);
	g_error_free(err);
}

static gboolean
fb_mqtt_cb_timeout(gpointer data)
{
	FbMqtt *mqtt = data;
	FbMqttPrivate *priv = mqtt->priv;

	priv->tev = 0;
	fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, _("Connection timed out"));
	return FALSE;
}

static void
fb_mqtt_timeout_clear(FbMqtt *mqtt)
{
	FbMqttPrivate *priv = mqtt->priv;

	if (priv->tev > 0) {
		g_source_remove(priv->tev);
		priv->tev = 0;
	}
}

static void
fb_mqtt_timeout(FbMqtt *mqtt)
{
	FbMqttPrivate *priv = mqtt->priv;

	fb_mqtt_timeout_clear(mqtt);
	priv->tev = g_timeout_add(FB_MQTT_TIMEOUT_CONN,
	                               fb_mqtt_cb_timeout, mqtt);
}

static gboolean
fb_mqtt_cb_ping(gpointer data)
{
	FbMqtt *mqtt = data;
	FbMqttMessage *msg;
	FbMqttPrivate *priv = mqtt->priv;

	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PINGREQ, 0);
	fb_mqtt_write(mqtt, msg);
	g_object_unref(msg);

	priv->tev = 0;
	fb_mqtt_timeout(mqtt);
	return FALSE;
}

static void
fb_mqtt_ping(FbMqtt *mqtt)
{
	FbMqttPrivate *priv = mqtt->priv;

	fb_mqtt_timeout_clear(mqtt);
	priv->tev = g_timeout_add(FB_MQTT_TIMEOUT_PING,
	                               fb_mqtt_cb_ping, mqtt);
}

static void
fb_mqtt_cb_fill(GObject *source, GAsyncResult *res, gpointer data)
{
	GBufferedInputStream *input = G_BUFFERED_INPUT_STREAM(source);
	FbMqtt *mqtt = data;
	gssize ret;
	GError *err = NULL;

	ret = g_buffered_input_stream_fill_finish(input, res, &err);

	if (ret < 1) {
		if (ret == 0) {
			err = g_error_new_literal(G_IO_ERROR,
					G_IO_ERROR_CONNECTION_CLOSED,
					_("Connection closed"));
		}

		fb_mqtt_take_error(mqtt, err, _("Failed to read fixed header"));
		return;
	}

	fb_mqtt_read_packet(mqtt);
}

static void
fb_mqtt_cb_read_packet(GObject *source, GAsyncResult *res, gpointer data)
{
	FbMqtt *mqtt = data;
	FbMqttPrivate *priv;
	gssize ret;
	FbMqttMessage *msg;
	GError *err = NULL;

	ret = g_input_stream_read_finish(G_INPUT_STREAM(source), res, &err);

	if (ret < 1) {
		if (ret == 0) {
			err = g_error_new_literal(G_IO_ERROR,
					G_IO_ERROR_CONNECTION_CLOSED,
					_("Connection closed"));
		}

		fb_mqtt_take_error(mqtt, err, _("Failed to read packet data"));
		return;
	}

	priv = mqtt->priv;
	priv->remz -= ret;

	if (priv->remz > 0) {
		g_input_stream_read_async(G_INPUT_STREAM(source),
				priv->rbuf->data +
				priv->rbuf->len - priv->remz, priv->remz,
				G_PRIORITY_DEFAULT, priv->cancellable,
				fb_mqtt_cb_read_packet, mqtt);
		return;
	}

	msg = fb_mqtt_message_new_bytes(priv->rbuf);

	if (G_UNLIKELY(msg == NULL)) {
		fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
		              _("Failed to parse message"));
		return;
	}

	fb_mqtt_read(mqtt, msg);
	g_object_unref(msg);

	/* Read another packet if connection wasn't reset in fb_mqtt_read() */
	if (fb_mqtt_connected(mqtt, FALSE)) {
		fb_mqtt_read_packet(mqtt);
	}
}

static void
fb_mqtt_read_packet(FbMqtt *mqtt)
{
	FbMqttPrivate *priv = mqtt->priv;
	const guint8 const *buf;
	gsize count = 0;
	gsize pos;
	guint mult = 1;
	guint8 byte;
	gsize size = 0;

	buf = g_buffered_input_stream_peek_buffer(priv->input, &count);

	/* Start at 1 to skip the first byte */
	pos = 1;

	do {
		if (pos >= count) {
			/* Not enough data yet, try again later */
			g_buffered_input_stream_fill_async(priv->input, -1,
					G_PRIORITY_DEFAULT, priv->cancellable,
					fb_mqtt_cb_fill, mqtt);
			return;
		}

		byte = *(buf + pos++);

		size += (byte & 127) * mult;
		mult *= 128;
	} while ((byte & 128) != 0);

	/* Add header to size */
	size += pos;

	g_byte_array_set_size(priv->rbuf, size);
	priv->remz = size;

	/* TODO: Use g_input_stream_read_all_async() when available. */
	/* TODO: Alternately, it would be nice to let the
	 * FbMqttMessage directly use the GBufferedInputStream
	 * buffer instead of copying it, provided it's consumed
	 * before the next read.
	 */
	g_input_stream_read_async(G_INPUT_STREAM(priv->input),
			priv->rbuf->data, priv->rbuf->len,
			G_PRIORITY_DEFAULT, priv->cancellable,
			fb_mqtt_cb_read_packet, mqtt);
}

void
fb_mqtt_read(FbMqtt *mqtt, FbMqttMessage *msg)
{
	FbMqttMessage *nsg;
	FbMqttPrivate *priv;
	FbMqttMessagePrivate *mriv;
	GByteArray *wytes;
	gchar *str;
	guint8 chr;
	guint16 mid;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
	priv = mqtt->priv;
	mriv = msg->priv;

	fb_util_debug_hexdump(FB_UTIL_DEBUG_INFO, mriv->bytes,
	                      "Reading %d (flags: 0x%0X)",
			      mriv->type, mriv->flags);

	switch (mriv->type) {
	case FB_MQTT_MESSAGE_TYPE_CONNACK:
		if (!fb_mqtt_message_read_byte(msg, NULL) ||
		    !fb_mqtt_message_read_byte(msg, &chr))
		{
			break;
		}

		if (chr != FB_MQTT_ERROR_SUCCESS) {
			fb_mqtt_error(mqtt, chr, _("Connection failed (%u)"),
			              chr);
			return;
		}

		priv->connected = TRUE;
		fb_mqtt_ping(mqtt);
		g_signal_emit_by_name(mqtt, "connect");
		return;

	case FB_MQTT_MESSAGE_TYPE_PUBLISH:
		if (!fb_mqtt_message_read_str(msg, &str)) {
			break;
		}

		if ((mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS1) ||
		    (mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS2))
		{
			if (mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS1) {
				chr = FB_MQTT_MESSAGE_TYPE_PUBACK;
			} else {
				chr = FB_MQTT_MESSAGE_TYPE_PUBREC;
			}

			if (!fb_mqtt_message_read_mid(msg, &mid)) {
				g_free(str);
				break;
			}

			nsg = fb_mqtt_message_new(chr, 0);
			fb_mqtt_message_write_u16(nsg, mid);
			fb_mqtt_write(mqtt, nsg);
			g_object_unref(nsg);
		}

		wytes = g_byte_array_new();
		fb_mqtt_message_read_r(msg, wytes);
		g_signal_emit_by_name(mqtt, "publish", str, wytes);
		g_byte_array_free(wytes, TRUE);
		g_free(str);
		return;

	case FB_MQTT_MESSAGE_TYPE_PUBREL:
		if (!fb_mqtt_message_read_mid(msg, &mid)) {
			break;
		}

		nsg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PUBCOMP, 0);
		fb_mqtt_message_write_u16(nsg, mid); /* Message identifier */
		fb_mqtt_write(mqtt, nsg);
		g_object_unref(nsg);
		return;

	case FB_MQTT_MESSAGE_TYPE_PINGRESP:
		fb_mqtt_ping(mqtt);
		return;

	case FB_MQTT_MESSAGE_TYPE_PUBACK:
	case FB_MQTT_MESSAGE_TYPE_PUBCOMP:
	case FB_MQTT_MESSAGE_TYPE_SUBACK:
	case FB_MQTT_MESSAGE_TYPE_UNSUBACK:
		return;

	default:
		fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
		              _("Unknown packet (%u)"), mriv->type);
		return;
	}

	/* Since no case returned, there was a parse error. */
	fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
	              _("Failed to parse message"));
}

static void
fb_mqtt_cb_flush(GObject *source, GAsyncResult *res, gpointer data)
{
	FbMqtt *mqtt = data;
	GError *err = NULL;

	if (!g_output_stream_flush_finish(G_OUTPUT_STREAM(source),
			res, &err)) {
		fb_mqtt_take_error(mqtt, err, _("Failed to write data"));
		return;
	}
}

void
fb_mqtt_write(FbMqtt *mqtt, FbMqttMessage *msg)
{
	const GByteArray *bytes;
	FbMqttMessagePrivate *mriv;
	FbMqttPrivate *priv;
	GBytes *gbytes;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
	priv = mqtt->priv;
	mriv = msg->priv;

	bytes = fb_mqtt_message_bytes(msg);

	if (G_UNLIKELY(bytes == NULL)) {
		fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
		              _("Failed to format data"));
		return;
	}

	fb_util_debug_hexdump(FB_UTIL_DEBUG_INFO, mriv->bytes,
	                      "Writing %d (flags: 0x%0X)",
		              mriv->type, mriv->flags);

 	/* TODO: Would be nice to refactor this to not require copying bytes */
	gbytes = g_bytes_new(bytes->data, bytes->len);
	purple_queued_output_stream_push_bytes(priv->output, gbytes);
	g_bytes_unref(gbytes);

	if (!g_output_stream_has_pending(G_OUTPUT_STREAM(priv->output))) {
		g_output_stream_flush_async(G_OUTPUT_STREAM(priv->output),
				G_PRIORITY_DEFAULT, priv->cancellable,
				fb_mqtt_cb_flush, mqtt);
	}
}

static void
fb_mqtt_cb_open(GObject *source, GAsyncResult *res, gpointer data)
{
	FbMqtt *mqtt = data;
	FbMqttPrivate *priv;
	GSocketConnection *conn;
	GError *err = NULL;

	conn = g_socket_client_connect_to_host_finish(G_SOCKET_CLIENT(source),
			res, &err);

	if (conn == NULL) {
		fb_mqtt_take_error(mqtt, err, NULL);
		return;
	}

	fb_mqtt_timeout_clear(mqtt);

	priv = mqtt->priv;
	priv->conn = G_IO_STREAM(conn);
	priv->input = G_BUFFERED_INPUT_STREAM(g_buffered_input_stream_new(
			g_io_stream_get_input_stream(priv->conn)));
	priv->output = purple_queued_output_stream_new(
			g_io_stream_get_output_stream(priv->conn));

	fb_mqtt_read_packet(mqtt);

	g_signal_emit_by_name(mqtt, "open");
}

void
fb_mqtt_open(FbMqtt *mqtt, const gchar *host, gint port)
{
	FbMqttPrivate *priv;
	PurpleAccount *acc;
	GSocketClient *client;
	GError *err = NULL;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	priv = mqtt->priv;

	acc = purple_connection_get_account(priv->gc);
	fb_mqtt_close(mqtt);

	client = purple_gio_socket_client_new(acc, &err);

	if (client == NULL) {
		fb_mqtt_take_error(mqtt, err, NULL);
		return;
	}

	priv->cancellable = g_cancellable_new();

	g_socket_client_set_tls(client, TRUE);
	g_socket_client_connect_to_host_async(client, host, port,
			priv->cancellable, fb_mqtt_cb_open, mqtt);
	g_object_unref(client);

	fb_mqtt_timeout(mqtt);
}

void
fb_mqtt_connect(FbMqtt *mqtt, guint8 flags, const GByteArray *pload)
{
	FbMqttMessage *msg;

	g_return_if_fail(!fb_mqtt_connected(mqtt, FALSE));
	g_return_if_fail(pload != NULL);

	/* Facebook always sends a CONNACK, use QoS1 */
	flags |= FB_MQTT_CONNECT_FLAG_QOS1;

	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_CONNECT, 0);
	fb_mqtt_message_write_str(msg, FB_MQTT_NAME);   /* Protocol name */
	fb_mqtt_message_write_byte(msg, FB_MQTT_LEVEL); /* Protocol level */
	fb_mqtt_message_write_byte(msg, flags);         /* Flags */
	fb_mqtt_message_write_u16(msg, FB_MQTT_KA);     /* Keep alive */

	fb_mqtt_message_write(msg, pload->data, pload->len);
	fb_mqtt_write(mqtt, msg);

	fb_mqtt_timeout(mqtt);
	g_object_unref(msg);
}

gboolean
fb_mqtt_connected(FbMqtt *mqtt, gboolean error)
{
	FbMqttPrivate *priv;
	gboolean connected;

	g_return_val_if_fail(FB_IS_MQTT(mqtt), FALSE);
	priv = mqtt->priv;
	connected = (priv->conn != NULL) && priv->connected;

	if (!connected && error) {
		fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
		              _("Not connected"));
	}

	return connected;
}

void
fb_mqtt_disconnect(FbMqtt *mqtt)
{
	FbMqttMessage *msg;

	if (G_UNLIKELY(!fb_mqtt_connected(mqtt, FALSE))) {
		return;
	}

	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_DISCONNECT, 0);
	fb_mqtt_write(mqtt, msg);
	g_object_unref(msg);
	fb_mqtt_close(mqtt);
}

void
fb_mqtt_publish(FbMqtt *mqtt, const gchar *topic, const GByteArray *pload)
{
	FbMqttMessage *msg;
	FbMqttPrivate *priv;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
	priv = mqtt->priv;

	/* Message identifier not required, but for consistency use QoS1 */
	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PUBLISH,
	                          FB_MQTT_MESSAGE_FLAG_QOS1);

	fb_mqtt_message_write_str(msg, topic);      /* Message topic */
	fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */

	if (pload != NULL) {
		fb_mqtt_message_write(msg, pload->data, pload->len);
	}

	fb_mqtt_write(mqtt, msg);
	g_object_unref(msg);
}

void
fb_mqtt_subscribe(FbMqtt *mqtt, const gchar *topic1, guint16 qos1, ...)
{
	const gchar *topic;
	FbMqttMessage *msg;
	FbMqttPrivate *priv;
	guint16 qos;
	va_list ap;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
	priv = mqtt->priv;

	/* Facebook requires a message identifier, use QoS1 */
	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_SUBSCRIBE,
	                          FB_MQTT_MESSAGE_FLAG_QOS1);

	fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */
	fb_mqtt_message_write_str(msg, topic1);     /* First topics */
	fb_mqtt_message_write_byte(msg, qos1);      /* First QoS value */

	va_start(ap, qos1);

	while ((topic = va_arg(ap, const gchar*)) != NULL) {
		qos = va_arg(ap, guint);
		fb_mqtt_message_write_str(msg, topic); /* Remaining topics */
		fb_mqtt_message_write_byte(msg, qos);  /* Remaining QoS values */
	}

	va_end(ap);

	fb_mqtt_write(mqtt, msg);
	g_object_unref(msg);
}

void
fb_mqtt_unsubscribe(FbMqtt *mqtt, const gchar *topic1, ...)
{
	const gchar *topic;
	FbMqttMessage *msg;
	FbMqttPrivate *priv;
	va_list ap;

	g_return_if_fail(FB_IS_MQTT(mqtt));
	g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
	priv = mqtt->priv;

	/* Facebook requires a message identifier, use QoS1 */
	msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE,
	                          FB_MQTT_MESSAGE_FLAG_QOS1);

	fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */
	fb_mqtt_message_write_str(msg, topic1);     /* First topic */

	va_start(ap, topic1);

	while ((topic = va_arg(ap, const gchar*)) != NULL) {
		fb_mqtt_message_write_str(msg, topic); /* Remaining topics */
	}

	va_end(ap);

	fb_mqtt_write(mqtt, msg);
	g_object_unref(msg);
}

FbMqttMessage *
fb_mqtt_message_new(FbMqttMessageType type, FbMqttMessageFlags flags)
{
	FbMqttMessage *msg;
	FbMqttMessagePrivate *priv;

	msg = g_object_new(FB_TYPE_MQTT_MESSAGE, NULL);
	priv = msg->priv;

	priv->type = type;
	priv->flags = flags;
	priv->bytes = g_byte_array_new();
	priv->local = TRUE;

	return msg;
}

FbMqttMessage *
fb_mqtt_message_new_bytes(GByteArray *bytes)
{
	FbMqttMessage *msg;
	FbMqttMessagePrivate *priv;
	guint8 *byte;

	g_return_val_if_fail(bytes != NULL, NULL);
	g_return_val_if_fail(bytes->len >= 2, NULL);

	msg = g_object_new(FB_TYPE_MQTT_MESSAGE, NULL);
	priv = msg->priv;

	priv->bytes = bytes;
	priv->local = FALSE;
	priv->type = (*bytes->data & 0xF0) >> 4;
	priv->flags = *bytes->data & 0x0F;

	/* Skip the fixed header */
	for (byte = priv->bytes->data + 1; (*(byte++) & 128) != 0; );
	priv->offset = byte - bytes->data;
	priv->pos = priv->offset;

	return msg;
}

void
fb_mqtt_message_reset(FbMqttMessage *msg)
{
	FbMqttMessagePrivate *priv;

	g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
	priv = msg->priv;

	if (priv->offset > 0) {
		g_byte_array_remove_range(priv->bytes, 0, priv->offset);
		priv->offset = 0;
		priv->pos = 0;
	}
}

const GByteArray *
fb_mqtt_message_bytes(FbMqttMessage *msg)
{
	FbMqttMessagePrivate *priv;
	guint i;
	guint8 byte;
	guint8 sbuf[4];
	guint32 size;

	g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), NULL);
	priv = msg->priv;

	i = 0;
	size = priv->bytes->len - priv->offset;

	do {
		if (G_UNLIKELY(i >= G_N_ELEMENTS(sbuf))) {
			return NULL;
		}

		byte = size % 128;
		size /= 128;

		if (size > 0) {
			byte |= 128;
		}

		sbuf[i++] = byte;
	} while (size > 0);

	fb_mqtt_message_reset(msg);
	g_byte_array_prepend(priv->bytes, sbuf, i);

	byte = ((priv->type & 0x0F) << 4) | (priv->flags & 0x0F);
	g_byte_array_prepend(priv->bytes, &byte, sizeof byte);

	priv->pos = (i + 1) * (sizeof byte);
	return priv->bytes;
}

gboolean
fb_mqtt_message_read(FbMqttMessage *msg, gpointer data, guint size)
{
	FbMqttMessagePrivate *priv;

	g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), FALSE);
	priv = msg->priv;

	if ((priv->pos + size) > priv->bytes->len) {
		return FALSE;
	}

	if ((data != NULL) && (size > 0)) {
		memcpy(data, priv->bytes->data + priv->pos, size);
	}

	priv->pos += size;
	return TRUE;
}

gboolean
fb_mqtt_message_read_r(FbMqttMessage *msg, GByteArray *bytes)
{
	FbMqttMessagePrivate *priv;
	guint size;

	g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), FALSE);
	priv = msg->priv;
	size = priv->bytes->len - priv->pos;

	if (G_LIKELY(size > 0)) {
		g_byte_array_append(bytes, priv->bytes->data + priv->pos,
		                    size);
	}

	return TRUE;
}

gboolean
fb_mqtt_message_read_byte(FbMqttMessage *msg, guint8 *value)
{
	return fb_mqtt_message_read(msg, value, sizeof *value);
}

gboolean
fb_mqtt_message_read_mid(FbMqttMessage *msg, guint16 *value)
{
	return fb_mqtt_message_read_u16(msg, value);
}

gboolean
fb_mqtt_message_read_u16(FbMqttMessage *msg, guint16 *value)
{
	if (!fb_mqtt_message_read(msg, value, sizeof *value)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = g_ntohs(*value);
	}

	return TRUE;
}

gboolean
fb_mqtt_message_read_str(FbMqttMessage *msg, gchar **value)
{
	guint8 *data;
	guint16 size;

	if (!fb_mqtt_message_read_u16(msg, &size)) {
		return FALSE;
	}

	if (value != NULL) {
		data = g_new(guint8, size + 1);
		data[size] = 0;
	} else {
		data = NULL;
	}

	if (!fb_mqtt_message_read(msg, data, size)) {
		g_free(data);
		return FALSE;
	}

	if (value != NULL) {
		*value = (gchar *) data;
	}

	return TRUE;
}

void
fb_mqtt_message_write(FbMqttMessage *msg, gconstpointer data, guint size)
{
	FbMqttMessagePrivate *priv;

	g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
	priv = msg->priv;

	g_byte_array_append(priv->bytes, data, size);
	priv->pos += size;
}

void
fb_mqtt_message_write_byte(FbMqttMessage *msg, guint8 value)
{
	fb_mqtt_message_write(msg, &value, sizeof value);
}

void
fb_mqtt_message_write_mid(FbMqttMessage *msg, guint16 *value)
{
	g_return_if_fail(value != NULL);
	fb_mqtt_message_write_u16(msg, ++(*value));
}

void
fb_mqtt_message_write_u16(FbMqttMessage *msg, guint16 value)
{
	value = g_htons(value);
	fb_mqtt_message_write(msg, &value, sizeof value);
}

void
fb_mqtt_message_write_str(FbMqttMessage *msg, const gchar *value)
{
	gint16 size;

	g_return_if_fail(value != NULL);

	size = strlen(value);
	fb_mqtt_message_write_u16(msg, size);
	fb_mqtt_message_write(msg, value, size);
}
