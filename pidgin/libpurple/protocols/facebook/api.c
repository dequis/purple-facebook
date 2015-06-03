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

#include <json-glib/json-glib.h>
#include <stdarg.h>
#include <string.h>

#include "api.h"
#include "http.h"
#include "json.h"
#include "marshal.h"
#include "thrift.h"
#include "util.h"

enum
{
	PROP_0,

	PROP_CID,
	PROP_CUID,
	PROP_MID,
	PROP_STOKEN,
	PROP_TOKEN,
	PROP_UID,

	PROP_N
};

struct _FbApiPrivate
{
	PurpleConnection *gc;
	FbMqtt *mqtt;

	FbId uid;
	guint64 mid;
	gchar *cid;
	gchar *cuid;
	gchar *stoken;
	gchar *token;

};

G_DEFINE_TYPE(FbApi, fb_api, G_TYPE_OBJECT);

static void
fb_api_set_property(GObject *obj, guint prop, const GValue *val,
                    GParamSpec *pspec)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	switch (prop) {
	case PROP_CID:
		g_free(priv->cid);
		priv->cid = g_value_dup_string(val);
		break;
	case PROP_CUID:
		g_free(priv->cuid);
		priv->cuid = g_value_dup_string(val);
		break;
	case PROP_MID:
		priv->mid = g_value_get_uint64(val);
		break;
	case PROP_STOKEN:
		g_free(priv->stoken);
		priv->stoken = g_value_dup_string(val);
		break;
	case PROP_TOKEN:
		g_free(priv->token);
		priv->token = g_value_dup_string(val);
		break;
	case PROP_UID:
		priv->uid = g_value_get_int64(val);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
		break;
	}
}

static void
fb_api_get_property(GObject *obj, guint prop, GValue *val, GParamSpec *pspec)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	switch (prop) {
	case PROP_CID:
		g_value_set_string(val, priv->cid);
		break;
	case PROP_CUID:
		g_value_set_string(val, priv->cuid);
		break;
	case PROP_MID:
		g_value_set_uint64(val, priv->mid);
		break;
	case PROP_STOKEN:
		g_value_set_string(val, priv->stoken);
		break;
	case PROP_TOKEN:
		g_value_set_string(val, priv->token);
		break;
	case PROP_UID:
		g_value_set_int64(val, priv->uid);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
		break;
	}
}


static void
fb_api_dispose(GObject *obj)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	if (G_LIKELY(priv->gc != NULL)) {
		purple_http_conn_cancel_all(priv->gc);
	}

	if (G_UNLIKELY(priv->mqtt != NULL)) {
		g_object_unref(priv->mqtt);
	}

	g_free(priv->cid);
	g_free(priv->cuid);
	g_free(priv->stoken);
	g_free(priv->token);
}

static void
fb_api_class_init(FbApiClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);
	GParamSpec *props[PROP_N] = {NULL};

	gklass->set_property = fb_api_set_property;
	gklass->get_property = fb_api_get_property;
	gklass->dispose = fb_api_dispose;
	g_type_class_add_private(klass, sizeof (FbApiPrivate));

	props[PROP_CID] = g_param_spec_string(
		"cid",
		"Client ID",
		"Client identifier for MQTT",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_CUID] = g_param_spec_string(
		"cuid",
		"Client Unique ID",
		"Client unique identifier for the MQTT queue",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_MID] = g_param_spec_uint64(
		"mid",
		"MQTT ID",
		"MQTT identifier for the MQTT queuer",
		0, G_MAXUINT64, 0,
		G_PARAM_READWRITE);
	props[PROP_STOKEN] = g_param_spec_string(
		"stoken",
		"Sync Token",
		"Synchronization token for the MQTT queue",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_TOKEN] = g_param_spec_string(
		"token",
		"Access Token",
		"Access token from authenticating",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_UID] = g_param_spec_int64(
		"uid",
		"User ID",
		"User identifier",
		0, G_MAXINT64, 0,
		G_PARAM_READWRITE);
	g_object_class_install_properties(gklass, PROP_N, props);

	g_signal_new("auth",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__VOID,
	             G_TYPE_NONE,
	             0);
	g_signal_new("connect",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__VOID,
	             G_TYPE_NONE,
	             0);
	g_signal_new("contacts",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("error",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__OBJECT,
	             G_TYPE_NONE,
	             1, G_TYPE_ERROR);
	g_signal_new("message",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("presence",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("thread-create",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__INT64,
	             G_TYPE_NONE,
	             1, FB_TYPE_ID);
	g_signal_new("thread-info",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("thread-list",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("typing",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
}

static void
fb_api_init(FbApi *api)
{
	FbApiPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(api, FB_TYPE_API, FbApiPrivate);
	api->priv = priv;
}

GQuark
fb_api_error_quark(void)
{
	static GQuark q;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-api-error-quark");
	}

	return q;
}

static gboolean
fb_api_json_chk(FbApi *api, gconstpointer data, gsize size, JsonNode **node)
{
	const gchar *msg;
	FbApiPrivate *priv;
	GError *err = NULL;
	gint64 code;
	JsonNode *root;

	g_return_val_if_fail(FB_IS_API(api), FALSE);
	priv = api->priv;

	root = fb_json_node_new(data, size, &err);
	FB_API_ERROR_CHK(api, err, return FALSE);

	if (fb_json_node_chk_int(root, "$.error_code", &code)) {
		if (!fb_json_node_chk_str(root, "$.error_msg", &msg)) {
			msg = _("Generic error");
		}

		fb_api_error(api, FB_API_ERROR_GENERAL, "%s", msg);
		json_node_free(root);
		return FALSE;
	}

	if (fb_json_node_chk_str(root, "$.errorCode", &msg)) {
		if ((g_ascii_strcasecmp(msg, "ERROR_QUEUE_NOT_FOUND") == 0) ||
		    (g_ascii_strcasecmp(msg, "ERROR_QUEUE_LOST") == 0))
		{
			g_free(priv->stoken);
			priv->stoken = NULL;
		}

		fb_api_error(api, FB_API_ERROR_GENERAL, "%s", msg);
		json_node_free(root);
		return FALSE;
	}

	if (node != NULL) {
		*node = root;
	}

	return TRUE;
}

static gboolean
fb_api_http_chk(FbApi *api, PurpleHttpResponse *res, JsonNode **root)
{
	const gchar *data;
	GError *err = NULL;
	gsize size;

	if ((res != NULL) && !fb_http_error_chk(res, &err)) {
		FB_API_ERROR_CHK(api, err, return FALSE);
	}

	if (root != NULL) {
		data = purple_http_response_get_data(res, &size);

		if (!fb_api_json_chk(api, data, size, root)) {
			return FALSE;
		}
	}

	return TRUE;
}

static PurpleHttpConnection *
fb_api_http_req(FbApi *api, const FbApiHttpInfo *info,
                FbHttpParams *params, const gchar *url)
{
	FbApiPrivate *priv = api->priv;
	gchar *data;
	gchar *key;
	gchar *val;
	GList *keys;
	GList *l;
	gsize size;
	GString *gstr;
	PurpleHttpConnection *ret;
	PurpleHttpRequest *req;

	fb_http_params_set_str(params, "api_key", FB_API_KEY);
	fb_http_params_set_str(params, "client_country_code", "US");
	fb_http_params_set_str(params, "fb_api_caller_class", info->klass);
	fb_http_params_set_str(params, "fb_api_req_friendly_name", info->name);
	fb_http_params_set_str(params, "format", "json");
	fb_http_params_set_str(params, "locale", "en_US");
	fb_http_params_set_str(params, "method", info->method);

	req = purple_http_request_new(url);
	purple_http_request_set_method(req, "POST");

	/* Ensure an old signature is not computed */
	g_hash_table_remove(params, "sig");

	gstr = g_string_new(NULL);
	keys = g_hash_table_get_keys(params);
	keys = g_list_sort(keys, (GCompareFunc) g_ascii_strcasecmp);

	for (l = keys; l != NULL; l = l->next) {
		key = l->data;
		val = g_hash_table_lookup(params, key);
		g_string_append_printf(gstr, "%s=%s", key, val);
	}

	g_string_append(gstr, FB_API_SECRET);
	data = g_compute_checksum_for_string(G_CHECKSUM_MD5, gstr->str,
	                                     gstr->len);
	fb_http_params_set_str(params, "sig", data);
	g_string_free(gstr, TRUE);
	g_free(data);

	data = fb_http_params_close(params, &size);
	purple_http_request_set_contents(req, data, size);
	g_free(data);

	if (priv->token != NULL) {
		data = g_strdup_printf("OAuth %s", priv->token);
		purple_http_request_header_set(req, "Authorization", data);
		g_free(data);
	}

	ret = purple_http_request(priv->gc, req, info->callback, api);
	purple_http_request_unref(req);
	return ret;
}

static void
fb_api_cb_http_bool(PurpleHttpConnection *con, PurpleHttpResponse *res,
                    gpointer data)
{
	const gchar *hata;
	FbApi *api = data;

	if (!fb_api_http_chk(api, res, NULL)) {
		return;
	}

	hata = purple_http_response_get_data(res, NULL);

	if (g_ascii_strcasecmp(hata, "true") != 0) {
		fb_api_error(api, FB_API_ERROR,
		             _("Failed generic API operation"));
	}
}

static void
fb_api_cb_mqtt_error(FbMqtt *mqtt, GError *error, gpointer data)
{
	FbApi *api = data;
	g_signal_emit_by_name(api, "error", error);
}

static void
fb_api_cb_mqtt_open(FbMqtt *mqtt, gpointer data)
{
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	gchar *json;
	JsonBuilder *bldr;

	static guint8 flags = FB_MQTT_CONNECT_FLAG_USER |
	                      FB_MQTT_CONNECT_FLAG_PASS |
	                      FB_MQTT_CONNECT_FLAG_CLR;

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_bool(bldr, "chat_on", TRUE);
	fb_json_bldr_add_bool(bldr, "fg", FALSE);
	fb_json_bldr_add_bool(bldr, "no_auto_fg", TRUE);
	fb_json_bldr_add_int(bldr, "mqtt_sid", priv->mid);
	fb_json_bldr_add_int(bldr, "nwt", 1);
	fb_json_bldr_add_int(bldr, "nwst", 0);
	fb_json_bldr_add_str(bldr, "a", FB_API_AGENT);
	fb_json_bldr_add_str(bldr, "d", priv->cuid);
	fb_json_bldr_add_str(bldr, "pf", "jz");
	fb_json_bldr_add_strf(bldr, "u", "%" FB_ID_FORMAT, priv->uid);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_mqtt_connect(mqtt,
		flags,       /* Flags */
		priv->cid,   /* Client identifier */
		json,        /* Will message */
		priv->token, /* Username */
		NULL);

	g_free(json);
}

static void
fb_api_cb_seqid(PurpleHttpConnection *con, PurpleHttpResponse *res,
                gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	gchar *json;
	GError *err = NULL;
	gint64 nid;
	JsonBuilder *bldr;
	JsonNode *root;

	static const gchar *expr =
		"$.data[0].fql_result_set[0].sync_sequence_id";

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	str = fb_json_node_get_str(root, expr, &err);
	FB_API_ERROR_CHK(api, err, return);
	nid = g_ascii_strtoll(str, NULL, 10);
	json_node_free(root);

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "delta_batch_size", 125);
	fb_json_bldr_add_int(bldr, "max_deltas_able_to_process", 1250);
	fb_json_bldr_add_int(bldr, "sync_api_version", 2);
	fb_json_bldr_add_str(bldr, "encoding", "JSON");

	if (priv->stoken == NULL) {
		fb_json_bldr_add_int(bldr, "initial_titan_sequence_id", nid);
		fb_json_bldr_add_str(bldr, "device_id", priv->cuid);
		fb_json_bldr_obj_begin(bldr, "device_params");
		fb_json_bldr_obj_end(bldr);

		json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
		fb_api_publish(api, "/messenger_sync_create_queue", "%s",
		               json);
		g_free(json);
		return;
	}

	fb_json_bldr_add_int(bldr, "last_seq_id", nid);
	fb_json_bldr_add_str(bldr, "sync_token", priv->stoken);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/messenger_sync_get_diffs", "%s", json);
	g_signal_emit_by_name(api, "connect");
	g_free(json);
}

static void
fb_api_cb_mqtt_connect(FbMqtt *mqtt, gpointer data)
{
	FbApi *api = data;
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_seqid,
		"com.facebook.orca.protocol.methods.u",
		"fetchThreadList",
		"GET"
	};

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_bool(bldr, "foreground", TRUE);
	fb_json_bldr_add_int(bldr, "keepalive_timeout", FB_MQTT_KA);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/foreground_state", "%s", json);
	g_free(json);

	fb_mqtt_subscribe(mqtt,
		"/inbox", 0,
		"/mercury", 0,
		"/messaging_events", 0,
		"/orca_presence", 0,
		"/orca_typing_notifications", 0,
		"/pp", 0,
		"/t_ms", 0,
		"/t_p", 0,
		"/t_rtc", 0,
		"/webrtc", 0,
		"/webrtc_response", 0,
		NULL
	);

	/* Notifications seem to lead to some sort of sending rate limit */
	fb_mqtt_unsubscribe(mqtt, "/orca_message_notifications", NULL);

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_str(bldr, "thread_list_ids",
		"SELECT sync_sequence_id "
			"FROM unified_thread "
			"WHERE folder='inbox' "
			"ORDER BY sync_sequence_id "
			"DESC LIMIT 1");
	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "q", json);
	fb_api_http_req(api, &info, prms, FB_API_URL_FQL);
	g_free(json);
}

static void
fb_api_cb_publish_tn(FbApi *api, const GByteArray *pload)
{
	const gchar *str;
	FbApiTyping typg;
	GError *err = NULL;
	gint64 state;
	gint64 uid;
	JsonNode *root;

	if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
		return;
	}

	if (!fb_json_node_chk_str(root, "$.type", &str) ||
	    (g_ascii_strcasecmp(str, "typ") != 0)) {
		goto finish;
	}

	uid = fb_json_node_get_int(root, "$.sender_fbid", &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	state = fb_json_node_get_int(root, "$.state", &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	typg.uid = uid;
	typg.state = state;
	g_signal_emit_by_name(api, "typing", &typg);

finish:
	json_node_free(root);
}

static void
fb_api_cb_publish_ms(FbApi *api, const GByteArray *pload)
{
	const gchar *str;
	FbApiMessage msg;
	FbApiPrivate *priv = api->priv;
	GError *err = NULL;
	gint64 tid;
	gint64 uid;
	GList *elms = NULL;
	GList *l;
	gpointer mptr;
	GSList *msgs = NULL;
	JsonArray *arr;
	JsonNode *mode;
	JsonNode *node;
	JsonNode *root;

	/* Start at 1 to skip the NULL byte */
	if (!fb_api_json_chk(api, pload->data + 1, pload->len - 1, &root)) {
		return;
	}

	if (fb_json_node_chk_str(root, "$.syncToken", &str)) {
		g_free(priv->stoken);
		priv->stoken = g_strdup(str);
		g_signal_emit_by_name(api, "connect");
		goto finish;
	}

	arr = fb_json_node_get_arr(root, "$.deltas", &err);
	FB_API_ERROR_CHK(api, err, goto finish);
	elms = json_array_get_elements(arr);

	for (l = elms; l != NULL; l = l->next) {
		node = l->data;

		if (!fb_json_node_chk(node, "$.deltaNewMessage", &node)) {
			continue;
		}

		mode = fb_json_node_get(node, "$.messageMetadata", &err);
		FB_API_ERROR_CHK(api, err, goto next);

		uid = fb_json_node_get_int(mode, "$.actorFbId", &err);
		FB_API_ERROR_CHK(api, err, goto next);

		if (uid == priv->uid) {
			goto next;
		}

		msg.uid = uid;
		msg.tid = 0;

		if (fb_json_node_chk_int(mode, "$.threadKey.threadFbId",
		                         &tid))
		{
			msg.tid = tid;
		}

		if (fb_json_node_chk_str(node, "$.body", &str)) {
			msg.text = str;
			mptr = g_memdup(&msg, sizeof msg);
			msgs = g_slist_prepend(msgs, mptr);
		}

		if (fb_json_node_chk_arr(node, "$.attachments", &arr) &&
		    (json_array_get_length(arr) > 0))
		{
			msg.text = _("* Non-Displayable Attachments *");
			mptr = g_memdup(&msg, sizeof msg);
			msgs = g_slist_prepend(msgs, mptr);
		}

next:
		json_node_free(node);
		json_node_free(mode);
	}

	msgs = g_slist_reverse(msgs);
	g_signal_emit_by_name(api, "message", msgs);

finish:
	g_list_free(elms);
	g_slist_free_full(msgs, g_free);
	json_node_free(root);
}

static void
fb_api_cb_publish_p(FbApi *api, const GByteArray *pload)
{
	FbApiPresence pres;
	FbThrift *thft;
	FbThriftType type;
	gint32 i32;
	gint64 i64;
	gpointer mptr;
	GSList *press;
	guint i;
	guint size;

	/* Start at 1 to skip the NULL byte */
	thft  = fb_thrift_new((GByteArray*) pload, 1, TRUE);
	press = NULL;

	/* Skip the full list boolean field */
	fb_thrift_read_field(thft, &type, NULL);
	g_warn_if_fail(type == FB_THRIFT_TYPE_BOOL);
	fb_thrift_read_bool(thft, NULL);

	/* Read the list field */
	fb_thrift_read_field(thft, &type, NULL);
	g_warn_if_fail(type == FB_THRIFT_TYPE_LIST);

	/* Read the list */
	fb_thrift_read_list(thft, &type, &size);
	g_warn_if_fail(type == FB_THRIFT_TYPE_STRUCT);

	for (i = 0; i < size; i++) {
		/* Read the user identifier field */
		fb_thrift_read_field(thft, &type, NULL);
		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, &i64);

		/* Read the active field */
		fb_thrift_read_field(thft, &type, NULL);
		g_warn_if_fail(type == FB_THRIFT_TYPE_I32);
		fb_thrift_read_i32(thft, &i32);

		pres.uid = i64;
		pres.active = i32 != 0;

		mptr = g_memdup(&pres, sizeof pres);
		press = g_slist_prepend(press, mptr);

		/* Skip the last active timestamp field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, NULL);

		/* Skip the active client bits field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I16);
		fb_thrift_read_i16(thft, NULL);

		/* Skip the VoIP compatibility bits field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, NULL);

		/* Read the field stop */
		fb_thrift_read_stop(thft);
	}

	/* Read the field stop */
	fb_thrift_read_stop(thft);
	g_object_unref(thft);

	press = g_slist_reverse(press);
	g_signal_emit_by_name(api, "presence", press);
	g_slist_free_full(press, g_free);
}

static void
fb_api_cb_mqtt_publish(FbMqtt *mqtt, const gchar *topic,
                       const GByteArray *pload, gpointer data)
{
	FbApi *api = data;
	gboolean comp;
	GByteArray *bytes;

	comp = fb_util_zcompressed(pload);

	if (G_LIKELY(comp)) {
		bytes = fb_util_zuncompress(pload);

		if (G_UNLIKELY(bytes == NULL)) {
			fb_api_error(api, FB_API_ERROR,
			             _("Failed to decompress"));
			return;
		}
	} else {
		bytes = (GByteArray*) pload;
	}

	if (g_ascii_strcasecmp(topic, "/orca_typing_notifications") == 0) {
		fb_api_cb_publish_tn(api, bytes);
	} else if (g_ascii_strcasecmp(topic, "/t_ms") == 0) {
		fb_api_cb_publish_ms(api, bytes);
	} else if (g_ascii_strcasecmp(topic, "/t_p") == 0) {
		fb_api_cb_publish_p(api, bytes);
	}

	if (G_LIKELY(comp)) {
		g_byte_array_free(bytes, TRUE);
	}
}

FbApi *
fb_api_new(PurpleConnection *gc)
{
	FbApi *api;
	FbApiPrivate *priv;

	api = g_object_new(FB_TYPE_API, NULL);
	priv = api->priv;

	priv->gc = gc;
	priv->mqtt = fb_mqtt_new(gc);

	g_signal_connect(priv->mqtt,
	                 "connect",
	                 G_CALLBACK(fb_api_cb_mqtt_connect),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "error",
	                 G_CALLBACK(fb_api_cb_mqtt_error),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "open",
	                 G_CALLBACK(fb_api_cb_mqtt_open),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "publish",
	                 G_CALLBACK(fb_api_cb_mqtt_publish),
	                 api);

	return api;
}

void
fb_api_rehash(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	if (priv->cid == NULL) {
		priv->cid = fb_util_randstr(32);
	}

	if (priv->mid == 0) {
		priv->mid = g_random_int();
	}

	if (priv->cuid == NULL) {
		priv->cuid = purple_uuid_random();
	}

	if (strlen(priv->cid) > 20) {
		priv->cid = g_realloc_n(priv->cid , 21, sizeof *priv->cid);
		priv->cid[20] = 0;
	}
}

void
fb_api_error(FbApi *api, FbApiError error, const gchar *format, ...)
{
	gchar *str;
	GError *err = NULL;
	va_list ap;

	g_return_if_fail(FB_IS_API(api));

	va_start(ap, format);
	str = g_strdup_vprintf(format, ap);
	va_end(ap);

	g_set_error(&err, FB_API_ERROR, error, "%s", str);
	g_free(str);

	g_signal_emit_by_name(api, "error", err);
	g_error_free(err);
}

static void
fb_api_cb_auth(PurpleHttpConnection *con, PurpleHttpResponse *res,
               gpointer data)
{
	const gchar *token;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	GError *err = NULL;
	gint64 uid;
	JsonNode *root;

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	uid = fb_json_node_get_int(root, "$.uid", &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	token = fb_json_node_get_str(root, "$.access_token", &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	g_free(priv->token);
	priv->token = g_strdup(token);
	priv->uid = uid;
	g_signal_emit_by_name(api, "auth");

finish:
	json_node_free(root);
}

void
fb_api_auth(FbApi *api, const gchar *user, const gchar *pass)
{
	FbHttpParams *prms;

	static const FbApiHttpInfo info = {
		fb_api_cb_auth,
		"com.facebook.auth.protocol.d",
		"authenticate",
		"auth.login"
	};

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "email", user);
	fb_http_params_set_str(prms, "password", pass);
	fb_api_http_req(api, &info, prms, FB_API_URL_AUTH);
}

static void
fb_api_cb_contacts(PurpleHttpConnection *con, PurpleHttpResponse *res,
                   gpointer data)
{
	const gchar *name;
	const gchar *uid;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	FbApiUser user;
	GError *err = NULL;
	GList *elms = NULL;
	GList *l;
	gpointer mptr;
	GSList *users = NULL;
	JsonArray *arr;
	JsonNode *node;
	JsonNode *root;

	static const gchar *expr =
		"$.viewer.messenger_contacts.nodes";

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	arr = fb_json_node_get_arr(root, expr, &err);
	FB_API_ERROR_CHK(api, err, goto finish);
	elms = json_array_get_elements(arr);

	for (l = elms; l != NULL; l = l->next) {
		node = l->data;
		uid = fb_json_node_get_str(node, "$.represented_profile.id",
		                           &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		user.uid = FB_ID_FROM_STR(uid);

		if (user.uid == priv->uid) {
			continue;
		}

		name = fb_json_node_get_str(node, "$.structured_name.text",
		                            &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		user.name = name;

		mptr = g_memdup(&user, sizeof user);
		users = g_slist_prepend(users, mptr);
	}

	g_signal_emit_by_name(api, "contacts", users);

finish:
	g_list_free(elms);
	g_slist_free_full(users, g_free);
	json_node_free(root);
}

void
fb_api_contacts(FbApi *api)
{
	FbHttpParams *prms;

	static const FbApiHttpInfo info = {
		fb_api_cb_contacts,
		"com.facebook.contacts.service.d",
		"FetchContactsFullQuery",
		"get"
	};

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "query_id", FB_API_QRYID_CONTACTS);
	fb_http_params_set_str(prms, "query_params", "{}");
	fb_api_http_req(api, &info, prms, FB_API_URL_GQL);
}

void
fb_api_connect(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	fb_mqtt_open(priv->mqtt, FB_MQTT_HOST, FB_MQTT_PORT);
}

void
fb_api_disconnect(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	fb_mqtt_disconnect(priv->mqtt);
}

void
fb_api_message(FbApi *api, FbId id, gboolean thread, const gchar *msg)
{
	const gchar *tpfx;
	FbApiPrivate *priv;
	gchar *json;
	guint64 msgid;
	JsonBuilder *bldr;

	g_return_if_fail(FB_IS_API(api));
	g_return_if_fail(msg != NULL);
	priv = api->priv;

	msgid = FB_API_MSGID(g_get_real_time() / 1000, g_random_int());
	tpfx = thread ? "tfbid_" : "";

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "msgid", msgid);
	fb_json_bldr_add_str(bldr, "body", msg);
	fb_json_bldr_add_strf(bldr, "sender_fbid", "%" FB_ID_FORMAT, priv->uid);
	fb_json_bldr_add_strf(bldr, "to", "%s%" FB_ID_FORMAT, tpfx, id);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/send_message2", "%s", json);
	g_free(json);
}

void
fb_api_publish(FbApi *api, const gchar *topic, const gchar *fmt, ...)
{
	FbApiPrivate *priv;
	GByteArray *bytes;
	GByteArray *cytes;
	gchar *msg;
	va_list ap;

	g_return_if_fail(FB_IS_API(api));
	g_return_if_fail(topic != NULL);
	g_return_if_fail(fmt != NULL);
	priv = api->priv;

	va_start(ap, fmt);
	msg = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	bytes = g_byte_array_new_take((guint8*) msg, strlen(msg));
	cytes = fb_util_zcompress(bytes);
	fb_mqtt_publish(priv->mqtt, topic, cytes);

	g_byte_array_free(cytes, TRUE);
	g_byte_array_free(bytes, TRUE);
}

static void
fb_api_cb_thread_create(PurpleHttpConnection *con, PurpleHttpResponse *res,
                        gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbId tid;
	GError *err = NULL;
	JsonNode *root;

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	str = fb_json_node_get_str(root, "$.thread_fbid", &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	tid = FB_ID_FROM_STR(str);
	g_signal_emit_by_name(api, "thread-create", tid);

finish:
	json_node_free(root);
}

void
fb_api_thread_create(FbApi *api, GSList *uids)
{
	FbApiPrivate *priv;
	FbHttpParams *prms;
	FbId *uid;
	gchar *json;
	GSList *l;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_create,
		"ccom.facebook.orca.send.service.l",
		"createThread",
		"POST"
	};

	g_return_if_fail(FB_IS_API(api));
	g_warn_if_fail((uids != NULL) && (uids->next != NULL));
	priv = api->priv;

	bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
	fb_json_bldr_obj_begin(bldr, NULL);
	fb_json_bldr_add_str(bldr, "type", "id");
	fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, priv->uid);
	fb_json_bldr_obj_end(bldr);

	for (l = uids; l != NULL; l = l->next) {
		uid = l->data;
		fb_json_bldr_obj_begin(bldr, NULL);
		fb_json_bldr_add_str(bldr, "type", "id");
		fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, *uid);
		fb_json_bldr_obj_end(bldr);
	}

	json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);
	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "to", json);
	fb_api_http_req(api, &info, prms, FB_API_URL_FQL);
	g_free(json);
}

static void
fb_api_cb_thread_info(PurpleHttpConnection *con, PurpleHttpResponse *res,
                      gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	FbApiThread thrd;
	FbApiUser user;
	GError *err = NULL;
	GList *elms = NULL;
	GList *l;
	gpointer mptr;
	JsonArray *arr;
	JsonNode *mode;
	JsonNode *node;
	JsonNode *root;

	static const gchar *expr = "$.data[0].fql_result_set[0]";

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	memset(&thrd, 0, sizeof thrd);
	node = fb_json_node_get(root, expr, &err);
	FB_API_ERROR_CHK(api, err, goto finish);

	str = fb_json_node_get_str(node, "$.thread_fbid", &err);
	FB_API_ERROR_CHK(api, err, goto finish);
	thrd.tid = FB_ID_FROM_STR(str);

	if (fb_json_node_chk_str(node, "$.name", &str) && (strlen(str) > 0)) {
		thrd.topic = str;
	}

	arr = fb_json_node_get_arr(node, "$.participants", &err);
	FB_API_ERROR_CHK(api, err, goto finish);
	elms = json_array_get_elements(arr);

	for (l = elms; l != NULL; l = l->next) {
		mode = l->data;

		str = fb_json_node_get_str(mode, "$.user_id", &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		user.uid = FB_ID_FROM_STR(str);

		str = fb_json_node_get_str(mode, "$.name", &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		user.name = str;

		if (user.uid != priv->uid) {
			mptr = g_memdup(&user, sizeof user);
			thrd.users = g_slist_prepend(thrd.users, mptr);
		}
	}

	g_signal_emit_by_name(api, "thread-info", &thrd);

finish:
	g_list_free(elms);
	g_slist_free_full(thrd.users, g_free);
	json_node_free(node);
	json_node_free(root);
}

void
fb_api_thread_info(FbApi *api, FbId tid)
{
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_info,
		"com.facebook.orca.protocol.methods.u",
		"fetchThreadList",
		"GET"
	};

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_strf(bldr, "threads",
		"SELECT thread_fbid, participants, name "
			"FROM unified_thread "
			"WHERE thread_fbid='%" FB_ID_FORMAT "' "
			"LIMIT 1",
		tid);
	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "q", json);
	fb_api_http_req(api, &info, prms, FB_API_URL_FQL);
	g_free(json);
}

void
fb_api_thread_invite(FbApi *api, FbId tid, FbId uid)
{
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_http_bool,
		"com.facebook.orca.protocol.a",
		"addMembers",
		"POST"
	};

	bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
	fb_json_bldr_obj_begin(bldr, NULL);
	fb_json_bldr_add_str(bldr, "type", "id");
	fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, uid);
	fb_json_bldr_obj_end(bldr);
	json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "to", json);
	fb_http_params_set_strf(prms, "id", "t_id.%" FB_ID_FORMAT, tid);
	fb_api_http_req(api, &info, prms, FB_API_URL_PARTS);
	g_free(json);
}

static void
fb_api_cb_threads_free(FbApiThread *thrd)
{
	g_slist_free_full(thrd->users, g_free);
	g_free(thrd);
}

static void
fb_api_cb_thread_list(PurpleHttpConnection *con, PurpleHttpResponse *res,
                      gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	FbApiThread thrd;
	FbApiUser user;
	GError *err = NULL;
	GList *elms = NULL;
	GList *elms2 = NULL;
	GList *l;
	GList *m;
	gpointer mptr;
	GSList *thrds = NULL;
	JsonArray *arr;
	JsonArray *arr2;
	JsonNode *node;
	JsonNode *node2;
	JsonNode *root;

	static const gchar *expr = "$.data[0].fql_result_set";

	if (!fb_api_http_chk(api, res, &root)) {
		return;
	}

	arr = fb_json_node_get_arr(root, expr, &err);
	FB_API_ERROR_CHK(api, err, goto finish);
	elms = json_array_get_elements(arr);

	for (l = elms; l != NULL; l = l->next) {
		node = l->data;
		memset(&thrd, 0, sizeof thrd);

		str = fb_json_node_get_str(node, "$.thread_fbid", &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		thrd.tid = FB_ID_FROM_STR(str);

		if (fb_json_node_chk_str(node, "$.name", &str) &&
		    (strlen(str) > 0))
		{
			thrd.topic = str;
		}

		arr2 = fb_json_node_get_arr(node, "$.participants", &err);
		FB_API_ERROR_CHK(api, err, goto finish);
		elms2 = json_array_get_elements(arr2);

		for (m = elms2; m != NULL; m = m->next) {
			node2 = m->data;

			str = fb_json_node_get_str(node2, "$.user_id", &err);
			FB_API_ERROR_CHK(api, err, goto finish);
			user.uid = FB_ID_FROM_STR(str);

			str = fb_json_node_get_str(node2, "$.name", &err);
			FB_API_ERROR_CHK(api, err, goto finish);
			user.name = str;

			if (user.uid != priv->uid) {
				mptr = g_memdup(&user, sizeof user);
				thrd.users = g_slist_prepend(thrd.users, mptr);
			}
		}

		g_list_free(elms2);
		elms2 = NULL;

		mptr = g_memdup(&thrd, sizeof thrd);
		thrds = g_slist_prepend(thrds, mptr);
	}

	thrds = g_slist_reverse(thrds);
	g_signal_emit_by_name(api, "thread-list", thrds);

finish:
	g_list_free(elms2);
	g_list_free(elms);
	g_slist_free_full(thrds, (GDestroyNotify) fb_api_cb_threads_free);
	json_node_free(root);
}

void
fb_api_thread_list(FbApi *api, guint limit)
{
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_list,
		"com.facebook.orca.protocol.methods.u",
		"fetchThreadList",
		"GET"
	};

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_strf(bldr, "threads",
		"SELECT thread_fbid, participants, name "
			"FROM unified_thread "
			"WHERE folder='inbox' "
			"ORDER BY timestamp DESC "
			"LIMIT %u",
		limit);
	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "q", json);
	fb_api_http_req(api, &info, prms, FB_API_URL_FQL);
	g_free(json);
}

void
fb_api_thread_topic(FbApi *api, FbId tid, const gchar *topic)
{
	FbHttpParams *prms;

	static const FbApiHttpInfo info = {
		fb_api_cb_http_bool,
		"com.facebook.orca.protocol.a",
		"setThreadName",
		"messaging.setthreadname"
	};

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "name", topic);
	fb_http_params_set_strf(prms, "tid", "t_id.%" FB_ID_FORMAT, tid);
	fb_api_http_req(api, &info, prms, FB_API_URL_TOPIC);
}

void
fb_api_typing(FbApi *api, FbId uid, gboolean state)
{
	gchar *json;
	JsonBuilder *bldr;

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "state", state != 0);
	fb_json_bldr_add_strf(bldr, "to", "%" FB_ID_FORMAT, uid);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/typing", "%s", json);
	g_free(json);
}
