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
	FbThriftFlags flags;
	GByteArray *bytes;
	guint offset;
	guint pos;
	guint lastbool;
	gint16 lastid;
};

G_DEFINE_TYPE(FbThrift, fb_thrift, G_TYPE_OBJECT);

static void
fb_thrift_dispose(GObject *obj)
{
	FbThriftPrivate *priv = FB_THRIFT(obj)->priv;

	if (priv->flags & FB_THRIFT_FLAG_INTERNAL) {
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
fb_thrift_new(GByteArray *bytes, guint offset, gboolean compact)
{
	FbThrift *thft;
	FbThriftPrivate *priv;

	thft = g_object_new(FB_TYPE_THRIFT, NULL);
	priv = thft->priv;

	if (bytes != NULL) {
		priv->bytes  = bytes;
		priv->offset = offset;
	} else {
		priv->flags |= FB_THRIFT_FLAG_INTERNAL;
	}

	if (compact) {
		priv->flags |= FB_THRIFT_FLAG_COMPACT;
	}

	priv->pos = priv->offset;
	return thft;
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
fb_thrift_read_bool(FbThrift *thft, gboolean *bln)
{
	FbThriftPrivate *priv;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (bln != NULL) {
		*bln = FALSE;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		if (bln != NULL) {
			*bln = byte != 0;
		}

		return TRUE;
	}

	if ((priv->lastbool & 0x03) != 0x01) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		if (bln != NULL) {
			*bln = (byte & 0x0F) == 0x01;
		}

		return TRUE;
	}

	if (bln != NULL) {
		*bln = ((priv->lastbool & 0x04) >> 2) != 0;
	}

	priv->lastbool = 0;
	return TRUE;
}

gboolean
fb_thrift_read_byte(FbThrift *thft, guint8 *byte)
{
	if (byte != NULL) {
		*byte = 0;
	}

	return fb_thrift_read(thft, byte, sizeof *byte);
}

gboolean
fb_thrift_read_dbl(FbThrift *thft, gdouble *dbl)
{
	gint64 i64;

	/* Almost always 8, but check anyways */
	static const gsize size = MIN(sizeof dbl, sizeof i64);

	if (dbl != NULL) {
		*dbl = 0;
	}

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (dbl != NULL) {
		memcpy(&dbl, &i64, size);
	}

	return TRUE;
}

gboolean
fb_thrift_read_i16(FbThrift *thft, gint16 *i16)
{
	FbThriftPrivate *priv;
	gint64 i64;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (i16 != NULL) {
		*i16 = 0;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read(thft, i16, sizeof *i16)) {
			return FALSE;
		}

		if (i16 != NULL) {
			*i16 = GINT16_FROM_BE(*i16);
		}

		return TRUE;
	}

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (i16 != NULL) {
		*i16 = i64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi16(FbThrift *thft, guint16 *u16)
{
	guint64 u64;

	if (u16 != NULL) {
		*u16 = 0;
	}

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (u16 != NULL) {
		*u16 = u64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_i32(FbThrift *thft, gint32 *i32)
{
	FbThriftPrivate *priv;
	gint64 i64;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (i32 != NULL) {
		*i32 = 0;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read(thft, i32, sizeof *i32)) {
			return FALSE;
		}

		if (i32 != NULL) {
			*i32 = GINT32_FROM_BE(*i32);
		}

		return TRUE;
	}

	if (!fb_thrift_read_i64(thft, &i64)) {
		return FALSE;
	}

	if (i32 != NULL) {
		*i32 = i64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi32(FbThrift *thft, guint32 *u32)
{
	guint64 u64;

	if (u32 != NULL) {
		*u32 = 0;
	}

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (u32 != NULL) {
		*u32 = u64;
	}

	return TRUE;
}

gboolean
fb_thrift_read_i64(FbThrift *thft, gint64 *i64)
{
	FbThriftPrivate *priv;
	guint64 u64;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (i64 != NULL) {
		*i64 = 0;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read(thft, i64, sizeof *i64)) {
			return FALSE;
		}

		if (i64 != NULL) {
			*i64 = GINT64_FROM_BE(*i64);
		}

		return TRUE;
	}

	if (!fb_thrift_read_vi64(thft, &u64)) {
		return FALSE;
	}

	if (i64 != NULL) {
		/* Convert from zigzag to integer */
		*i64 = (u64 >> 0x01) ^ -(u64 & 0x01);
	}

	return TRUE;
}

gboolean
fb_thrift_read_vi64(FbThrift *thft, guint64 *u64)
{
	FbThriftPrivate *priv;
	guint i;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	priv = thft->priv;

	if (u64 != NULL) {
		*u64 = 0;
		 i = 0;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		return FALSE;
	}

	do {
		if (!fb_thrift_read_byte(thft, &byte)) {
			if (u64 != NULL) {
				*u64 = 0;
			}

			return FALSE;
		}

		if (u64 != NULL) {
			*u64 |= ((guint64) (byte & 0x7F)) << i;
			 i += 7;
		}
	} while ((byte & 0x80) == 0x80);

	return TRUE;
}

gboolean
fb_thrift_read_str(FbThrift *thft, gchar **str)
{
	gint32 size;
	guint8 *data;

	if (str != NULL) {
		*str = NULL;
	}

	if (!fb_thrift_read_i32(thft, &size)) {
		return FALSE;
	}

	if (str != NULL) {
		data = g_new(guint8, size + 1);
		data[size] = 0;
	} else {
		data = NULL;
	}

	if (!fb_thrift_read(thft, data, size)) {
		g_free(data);
		return FALSE;
	}

	if (str != NULL) {
		*str = (gchar*) data;
	}

	return TRUE;
}

gboolean
fb_thrift_read_field(FbThrift *thft, FbThriftType *type, gint16 *id)
{
	FbThriftPrivate *priv;
	gint16 i16;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	g_return_val_if_fail(type != NULL, FALSE);
	priv = thft->priv;

	if (id != NULL) {
		*id = 0;
	}

	if (!fb_thrift_read_byte(thft, &byte)) {
		*type = 0;
		return FALSE;
	}

	if (byte == FB_THRIFT_TYPE_STOP) {
		*type = byte;
		return FALSE;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		*type = byte;

		if (!fb_thrift_read_i16(thft, &i16)) {
			return FALSE;
		}

		if (id != NULL) {
			*id = i16;
		}

		return TRUE;
	}

	*type = fb_thrift_ct2t(byte & 0x0F);
	i16   = (byte & 0xF0) >> 4;

	if (*type == FB_THRIFT_TYPE_BOOL) {
		priv->lastbool = 0x01;

		if ((byte & 0x0F) == 0x01) {
			priv->lastbool |= 0x01 << 2;
		}

		return TRUE;
	}

	if (i16 == 0) {
		if (!fb_thrift_read_i16(thft, &i16)) {
			return FALSE;
		}
	} else {
		i16 = priv->lastid + i16;
	}

	if (id != NULL) {
		*id = i16;
	}

	priv->lastid = i16;
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
	FbThriftPrivate *priv;
	gint32 i32;
	guint8 byte;
	guint32 u32;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	g_return_val_if_fail(type != NULL, FALSE);
	g_return_val_if_fail(size != NULL, FALSE);
	priv = thft->priv;

	*type = 0;
	*size = 0;

	if (!fb_thrift_read_byte(thft, &byte)) {
		return FALSE;
	}

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read_i32(thft, &i32)) {
			return FALSE;
		}

		*type = byte;
		*size = i32;
		return TRUE;
	}

	*type = fb_thrift_ct2t(byte & 0x0F);
	*size = (byte & 0xF0) >> 4;

	if (*size == 15) {
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
	FbThriftPrivate *priv;
	gint32 i32;
	guint8 byte;

	g_return_val_if_fail(FB_IS_THRIFT(thft), FALSE);
	g_return_val_if_fail(ktype != NULL, FALSE);
	g_return_val_if_fail(vtype != NULL, FALSE);
	g_return_val_if_fail(size != NULL, FALSE);
	priv = thft->priv;

	*ktype = 0;
	*vtype = 0;
	*size = 0;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		*ktype = byte;

		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		*vtype = byte;

		if (!fb_thrift_read_i32(thft, &i32)) {
			return FALSE;
		}

		*size = i32;
		return TRUE;
	}

	if (!fb_thrift_read_i32(thft, &i32)) {
		return FALSE;
	}

	*size = i32;

	if (*size != 0) {
		if (!fb_thrift_read_byte(thft, &byte)) {
			return FALSE;
		}

		*ktype = fb_thrift_ct2t((byte & 0xF0) >> 4);
		*vtype = fb_thrift_ct2t(byte & 0x0F);
	} else {
		*ktype = 0;
		*vtype = 0;
	}

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
fb_thrift_write_bool(FbThrift *thft, gboolean bln)
{
	FbThriftPrivate *priv;
	guint pos;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		fb_thrift_write_byte(thft, bln != 0);
		return;
	}

	if ((priv->lastbool & 0x03) != 0x02) {
		fb_thrift_write_byte(thft, bln ? 0x01 : 0x02);
		return;
	}

	pos = priv->lastbool >> 3;
	priv->lastbool = 0;

	if ((pos >= priv->offset) && (pos < priv->bytes->len)) {
		priv->bytes->data[pos] &= ~0x0F;
		priv->bytes->data[pos] |= bln ? 0x01 : 0x02;
	}
}

void
fb_thrift_write_byte(FbThrift *thft, guint8 byte)
{
	fb_thrift_write(thft, &byte, sizeof byte);
}

void
fb_thrift_write_dbl(FbThrift *thft, gdouble dbl)
{
	gint64 i64;

	/* Almost always 8, but check anyways */
	static const gsize size = MIN(sizeof dbl, sizeof i64);

	memcpy(&i64, &dbl, size);
	fb_thrift_write_i64(thft, i64);
}

void
fb_thrift_write_i16(FbThrift *thft, gint16 i16)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		i16 = GINT16_TO_BE(i16);
		fb_thrift_write(thft, &i16, sizeof i16);
		return;
	}

	fb_thrift_write_i32(thft, i16);
}

void
fb_thrift_write_vi16(FbThrift *thft, guint16 u16)
{
	fb_thrift_write_vi32(thft, u16);
}

void
fb_thrift_write_i32(FbThrift *thft, gint32 i32)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		i32 = GINT32_TO_BE(i32);
		fb_thrift_write(thft, &i32, sizeof i32);
		return;
	}

	i32 = (i32 << 1) ^ (i32 >> 31);
	fb_thrift_write_vi64(thft, i32);
}

void
fb_thrift_write_vi32(FbThrift *thft, guint32 u32)
{
	fb_thrift_write_vi64(thft, u32);
}


void
fb_thrift_write_i64(FbThrift *thft, gint64 i64)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		i64 = GINT64_TO_BE(i64);
		fb_thrift_write(thft, &i64, sizeof i64);
		return;
	}

	i64 = (i64 << 1) ^ (i64 >> 63);
	fb_thrift_write_vi64(thft, i64);
}

void
fb_thrift_write_vi64(FbThrift *thft, guint64 u64)
{
	FbThriftPrivate *priv;
	gboolean last;
	guint8 byte;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		return;
	}

	do {
		last = (u64 & ~0x7F) == 0;
		byte = !last ? ((u64 & 0x7F) | 0x80) : (u64 & 0x0F);

		fb_thrift_write_byte(thft, byte);
		u64 >>= 7;
	} while (!last);
}

void
fb_thrift_write_str(FbThrift *thft, const gchar *str)
{
	guint32 size;

	g_return_if_fail(str != NULL);

	size = strlen(str);
	fb_thrift_write_vi32(thft, size);
	fb_thrift_write(thft, str, size);
}

void
fb_thrift_write_field(FbThrift *thft, FbThriftType type, gint16 id)
{
	FbThriftPrivate *priv;
	gint16 iddf;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		fb_thrift_write_byte(thft, type);
		fb_thrift_write_i16(thft, id);
		return;
	}

	if (type == FB_THRIFT_TYPE_BOOL) {
		priv->lastbool = (priv->pos << 3) | 0x02;
	}

	type = fb_thrift_t2ct(type);
	iddf = id - priv->lastid;

	if ((id <= priv->lastid) || (iddf > 15)) {
		fb_thrift_write_byte(thft, type);
		fb_thrift_write_i16(thft, id);
	} else {
		fb_thrift_write_byte(thft, (iddf << 4) | type);
	}

	priv->lastid = id;
}

void
fb_thrift_write_stop(FbThrift *thft)
{
	fb_thrift_write_byte(thft, FB_THRIFT_TYPE_STOP);
}

void
fb_thrift_write_list(FbThrift *thft, FbThriftType type, guint size)
{
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		fb_thrift_write_byte(thft, type);
		fb_thrift_write_i32(thft, size);
		return;
	}

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
	FbThriftPrivate *priv;

	g_return_if_fail(FB_IS_THRIFT(thft));
	priv = thft->priv;

	if (!(priv->flags & FB_THRIFT_FLAG_COMPACT)) {
		fb_thrift_write_byte(thft, ktype);
		fb_thrift_write_byte(thft, vtype);
		fb_thrift_write_i32(thft, size);
		return;
	}

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

	if (G_UNLIKELY(type >= G_N_ELEMENTS(types))) {
		return 0;
	}

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

	if (G_UNLIKELY(type >= G_N_ELEMENTS(types))) {
		return 0;
	}

	return types[type];
}
