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

#include <string.h>

#include "thrift.h"

struct _FbThriftPrivate
{
	GByteArray *bytes;
	gboolean internal;
	guint offset;
	guint pos;
	guint lastbool;
};

G_DEFINE_TYPE(FbThrift, fb_thrift, G_TYPE_OBJECT);

static void
fb_thrift_dispose(GObject *obj)
{
	FbThriftPrivate *priv = FB_THRIFT(obj)->priv;

	if (priv->internal) {
		g_byte_array_free(priv->bytes, TRUE);
	}
}

static void
fb_thrift_class_init(FbThriftClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);

	gklass->dispose = fb_thrift_dispose;
	g_type_class_add_private(klass, sizeof (FbThriftPrivate));
}

static void
fb_thrift_init(FbThrift *thft)
{
	FbThriftPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(thft, FB_TYPE_THRIFT,
	                                   FbThriftPrivate);
	thft->priv = priv;
}

FbThrift *
fb_thrift_new(GByteArray *bytes, guint offset)
{
	FbThrift *thft;
	FbThriftPrivate *priv;

	thft = g_object_new(FB_TYPE_THRIFT, NULL);
	priv = thft->priv;

	if (bytes != NULL) {
		priv->bytes = bytes;
		priv->offset = offset;
		priv->pos = offset;
	} else {
		priv->bytes = g_byte_array_new();
		priv->internal = TRUE;
	}

	return thft;
}

const GByteArray *
fb_thrift_get_bytes(FbThrift *thft)
{
	FbThriftPrivate *priv;

	g_return_val_if_fail(FB_IS_THRIFT(thft), NULL);
	priv = thft->priv;
	return priv->bytes;
}

guint
fb_thrift_get_pos(FbThrift *thft)
{
	FbThriftPrivate *priv;

	g_return_val_if_fail(FB_IS_THRIFT(thft), 0);
	priv = thft->priv;
	return priv->pos;
}

void
fb_thrift_set_pos(FbThrift *thft, guint pos)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;
	priv->pos = pos;
}

void
fb_thrift_reset(FbThrift *thft)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;
	priv->pos = priv->offset;
}

gboolean
fb_thrift_read(FbThrift *thft, gpointer data, guint size)
{
	FbThriftPrivate *priv;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

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
fb_thrift_read_bool(FbThrift *thft, gboolean *value)
{
	FbThriftPrivate *priv;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if ((priv->lastbool & 0x03) != 0x01) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		if (value != NULL) {
			*value = (byte & 0x0F) == 0x01;
		}

		priv->lastbool = 0;
		return TRUE;
	}

	if (value != NULL) {
		*value = ((priv->lastbool & 0x04) >> 2) != 0;
	}

	priv->lastbool = 0;
	return TRUE;
}

gboolean
fb_thrift_read_byte(FbThrift *thft, guint8 *value)
{
	return fb_thrift_read(thft, value, sizeof *value);
}

gboolean
fb_thrift_read_dbl(FbThrift *thft, gdouble *value)
{
	gint64 i64;

	/* Almost always 8, but check anyways */
	static const gsize size = MIN(sizeof value, sizeof i64);

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (value != NULL) {
		memcpy(value, &i64, size);
	}

	return TRUE;
}

gboolean
fb_thrift_read_i16(FbThrift *thft, gint16 *value)
{
	gint64 i64;

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = i64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi16(FbThrift *thft, guint16 *value)
{
	guint64 u64;

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = u64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_i32(FbThrift *thft, gint32 *value)
{
	gint64 i64;

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = i64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi32(FbThrift *thft, guint32 *value)
{
	guint64 u64;

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (value != NULL) {
		*value = u64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_i64(FbThrift *thft, gint64 *value)
{
	guint64 u64;

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (value != NULL) {
		/* Convert from zigzag to integer */
		*value = (u64 >> 0x01) ^ -(u64 & 0x01);
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi64(FbThrift *thft, guint64 *value)
{
	guint i = 0;
	guint8 byte;
	guint64 u64 = 0;

	do {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		u64 |= ((guint64) (byte & 0x7F)) << i;
		i += 7;
	} while ((byte & 0x80) == 0x80);

	if (value != NULL) {
		*value = u64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_str(FbThrift *thft, gchar **value)
{
	guint8 *data;
	guint32 size;

	if (!fb_thrift_read_vi32(thft, &size)) {
		return FALSE;
	}

	if (value != NULL) {
		data = g_new(guint8, size + 1);
		data[size] = 0;
	} else {
		data = NULL;
	}

	if (!fb_thrift_read(thft, data, size)) {
		g_free(data);
		return FALSE;
	}

	if (value != NULL) {
		*value = (gchar *) data;
	}

	return TRUE;
}

gboolean
fb_thrift_read_field(FbThrift *thft, FbThriftType *type, gint16 *id,
					 gint16 lastid)
{
	FbThriftPrivate *priv;
	gint16 i16;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	g_return_val_if_fail(type != NULL, FALSE);
	g_return_val_if_fail(id != NULL, FALSE);
	priv = thft->priv;

	if (!fb_thrift_read_byte(thft, &byte)) {
		return FALSE;
	}

	if (byte == FB_THRIFT_TYPE_STOP) {
		*type = FB_THRIFT_TYPE_STOP;
		return FALSE;
	}

	*type = fb_thrift_ct2t(byte & 0x0F);
	i16 = (byte & 0xF0) >> 4;

	if (i16 == 0) {
		if (!fb_thrift_read_i16(thft, id)) {
			return FALSE;
		}
	} else {
		*id = lastid + i16;
	}

	if (*type == FB_THRIFT_TYPE_BOOL) {
		priv->lastbool = 0x01;

		if ((byte & 0x0F) == 0x01) {
			priv->lastbool |= 0x01 << 2;
		}
	}

	return TRUE;
}

gboolean
fb_thrift_read_stop(FbThrift *thft)
{
	guint8 byte;

	return fb_thrift_read_byte(thft, &byte) &&
	       (byte == FB_THRIFT_TYPE_STOP);
}

gboolean
fb_thrift_read_isstop(FbThrift *thft)
{
	FbThriftPrivate *priv;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (!fb_thrift_read_byte(thft, &byte)) {
		return FALSE;
	}

	priv->pos--;
	return byte == FB_THRIFT_TYPE_STOP;
}

gboolean
fb_thrift_read_list(FbThrift *thft, FbThriftType *type, guint *size)
{
	guint8 byte;
	guint32 u32;

	g_return_val_if_fail(type != NULL, FALSE);
	g_return_val_if_fail(size != NULL, FALSE);

	if (!fb_thrift_read_byte(thft, &byte)) {
		return FALSE;
	}

	*type = fb_thrift_ct2t(byte & 0x0F);
	*size = (byte & 0xF0) >> 4;

	if (*size == 0x0F) {
		if (!fb_thrift_read_vi32(thft, &u32)) {
			return FALSE;
		}

		*size = u32;
	}

	return TRUE;
}

gboolean
fb_thrift_read_map(FbThrift *thft, FbThriftType *ktype, FbThriftType *vtype,
                   guint *size)
{
	gint32 i32;
	guint8 byte;

	g_return_val_if_fail(ktype != NULL, FALSE);
	g_return_val_if_fail(vtype != NULL, FALSE);
	g_return_val_if_fail(size != NULL, FALSE);

	if (!fb_thrift_read_i32(thft, &i32)) {
		return FALSE;
	}

	if (i32 != 0) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		*ktype = fb_thrift_ct2t((byte & 0xF0) >> 4);
		*vtype = fb_thrift_ct2t(byte & 0x0F);
	} else {
		*ktype = 0;
		*vtype = 0;
	}

	*size = i32;
	return TRUE;
}

gboolean
fb_thrift_read_set(FbThrift *thft, FbThriftType *type, guint *size)
{
	return fb_thrift_read_list(thft, type, size);
}

void
fb_thrift_write(FbThrift *thft, gconstpointer data, guint size)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	g_byte_array_append(priv->bytes, data, size);
	priv->pos += size;
}

void
fb_thrift_write_bool(FbThrift *thft, gboolean value)
{
	FbThriftPrivate *priv;
	guint pos;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if ((priv->lastbool & 0x03) != 0x02) {
		fb_thrift_write_byte(thft, value ? 0x01 : 0x02);
		return;
	}

	pos = priv->lastbool >> 3;
	priv->lastbool = 0;

	if ((pos >= priv->offset) && (pos < priv->bytes->len)) {
		priv->bytes->data[pos] &= ~0x0F;
		priv->bytes->data[pos] |= value ? 0x01 : 0x02;
	}
}

void
fb_thrift_write_byte(FbThrift *thft, guint8 value)
{
	fb_thrift_write(thft, &value, sizeof value);
}

void
fb_thrift_write_dbl(FbThrift *thft, gdouble value)
{
	gint64 i64;

	/* Almost always 8, but check anyways */
	static const gsize size = MIN(sizeof value, sizeof i64);

	memcpy(&i64, &value, size);
	fb_thrift_write_i64(thft, i64);
}

void
fb_thrift_write_i16(FbThrift *thft, gint16 value)
{
	fb_thrift_write_i64(thft, value);
}

void
fb_thrift_write_vi16(FbThrift *thft, guint16 value)
{
	fb_thrift_write_vi64(thft, value);
}

void
fb_thrift_write_i32(FbThrift *thft, gint32 value)
{
	value = (value << 1) ^ (value >> 31);
	fb_thrift_write_vi64(thft, value);
}

void
fb_thrift_write_vi32(FbThrift *thft, guint32 value)
{
	fb_thrift_write_vi64(thft, value);
}

void
fb_thrift_write_i64(FbThrift *thft, gint64 value)
{
	value = (value << 1) ^ (value >> 63);
	fb_thrift_write_vi64(thft, value);
}

void
fb_thrift_write_vi64(FbThrift *thft, guint64 value)
{
	gboolean last;
	guint8 byte;

	do {
		last = (value & ~0x7F) == 0;
		byte = value & 0x7F;

		if (!last) {
			byte |= 0x80;
			value >>= 7;
		}

		fb_thrift_write_byte(thft, byte);
	} while (!last);
}

void
fb_thrift_write_str(FbThrift *thft, const gchar *value)
{
	guint32 size;

	g_return_if_fail(value != NULL);

	size = strlen(value);
	fb_thrift_write_vi32(thft, size);
	fb_thrift_write(thft, value, size);
}

void
fb_thrift_write_field(FbThrift *thft, FbThriftType type, gint16 id,
					  gint16 lastid)
{
	FbThriftPrivate *priv;
	gint16 diff;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (type == FB_THRIFT_TYPE_BOOL) {
		priv->lastbool = (priv->pos << 3) | 0x02;
	}

	type = fb_thrift_t2ct(type);
	diff = id - lastid;

	if ((id <= lastid) || (diff > 0x0F)) {
		fb_thrift_write_byte(thft, type);
		fb_thrift_write_i16(thft, id);
	} else {
		fb_thrift_write_byte(thft, (diff << 4) | type);
	}
}

void
fb_thrift_write_stop(FbThrift *thft)
{
	fb_thrift_write_byte(thft, FB_THRIFT_TYPE_STOP);
}

void
fb_thrift_write_list(FbThrift *thft, FbThriftType type, guint size)
{
	type = fb_thrift_t2ct(type);

	if (size <= 14) {
		fb_thrift_write_byte(thft, (size << 4) | type);
		return;
	}

	fb_thrift_write_vi32(thft, size);
	fb_thrift_write_byte(thft, 0xF0 | type);
}

void
fb_thrift_write_map(FbThrift *thft, FbThriftType ktype, FbThriftType vtype,
                    guint size)
{
	if (size == 0) {
		fb_thrift_write_byte(thft, 0);
		return;
	}

	ktype = fb_thrift_t2ct(ktype);
	vtype = fb_thrift_t2ct(vtype);

	fb_thrift_write_vi32(thft, size);
	fb_thrift_write_byte(thft, (ktype << 4) | vtype);
}

void
fb_thrift_write_set(FbThrift *thft, FbThriftType type, guint size)
{
	fb_thrift_write_list(thft, type, size);
}

guint8
fb_thrift_t2ct(FbThriftType type)
{
	static const guint8 types[] = {
		[FB_THRIFT_TYPE_STOP]   = 0,
		[FB_THRIFT_TYPE_VOID]   = 0,
		[FB_THRIFT_TYPE_BOOL]   = 2,
		[FB_THRIFT_TYPE_BYTE]   = 3,
		[FB_THRIFT_TYPE_DOUBLE] = 7,
		[5]                     = 0,
		[FB_THRIFT_TYPE_I16]    = 4,
		[7]                     = 0,
		[FB_THRIFT_TYPE_I32]    = 5,
		[9]                     = 0,
		[FB_THRIFT_TYPE_I64]    = 6,
		[FB_THRIFT_TYPE_STRING] = 8,
		[FB_THRIFT_TYPE_STRUCT] = 12,
		[FB_THRIFT_TYPE_MAP]    = 11,
		[FB_THRIFT_TYPE_SET]    = 10,
		[FB_THRIFT_TYPE_LIST]   = 9
	};

	g_return_val_if_fail(type < G_N_ELEMENTS(types), 0);
	return types[type];
}

FbThriftType
fb_thrift_ct2t(guint8 type)
{
	static const guint8 types[] = {
		[0]  = FB_THRIFT_TYPE_STOP,
		[1]  = FB_THRIFT_TYPE_BOOL,
		[2]  = FB_THRIFT_TYPE_BOOL,
		[3]  = FB_THRIFT_TYPE_BYTE,
		[4]  = FB_THRIFT_TYPE_I16,
		[5]  = FB_THRIFT_TYPE_I32,
		[6]  = FB_THRIFT_TYPE_I64,
		[7]  = FB_THRIFT_TYPE_DOUBLE,
		[8]  = FB_THRIFT_TYPE_STRING,
		[9]  = FB_THRIFT_TYPE_LIST,
		[10] = FB_THRIFT_TYPE_SET,
		[11] = FB_THRIFT_TYPE_MAP,
		[12] = FB_THRIFT_TYPE_STRUCT
	};

	g_return_val_if_fail(type < G_N_ELEMENTS(types), 0);
	return types[type];
}
