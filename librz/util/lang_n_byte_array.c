#include <rz_util.h>

static void lang_n_byte_array_rizin(RzStrBuf *sb, const ut8 *buffer, const int n_bytes) {
	size_t pos = 0;
	rz_strbuf_append(sb, "wx ");

	for (pos = 0; pos < n_bytes; pos++) {
		rz_strbuf_appendf(sb, "%02x", buffer[pos]);
	}

	rz_strbuf_appendf(sb, " ; sd -%" PFMTSZd, pos);
}

/**
 * \brief Generates a string containing a byte array of N bytes in the specified language
 *
 * \param	buffer		The buffer to read
 * \param	size_max	The max amount of bytes to write
 * \param	type		The RzLangNByteArrayType type
 * \param	n_bytes		The number of bytes to write
 */
RZ_API RZ_OWN char *rz_lang_n_byte_array(RZ_NONNULL const ut8 *buffer, const ut32 size_max, RzLangNByteArrayType type, int n_bytes) {
	rz_return_val_if_fail(buffer, NULL);
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	if(n_bytes == 0) {
		RZ_LOG_ERROR("Length may not be 0\n");
		return rz_strbuf_drain_nofree(&sb);
	}

	if(n_bytes < 0) {
		n_bytes *= -1;
	}

	if(n_bytes >= size_max) {
		RZ_LOG_ERROR("Length exceeds max size (%u)\n", size_max);
		return rz_strbuf_drain_nofree(&sb);
	}

	switch(type) {
	case RZ_LANG_N_BYTE_ARRAY_RIZIN:
		lang_n_byte_array_rizin(&sb, buffer, n_bytes);
		break;
	default:
		rz_strbuf_fini(&sb);
		rz_warn_if_reached();
		return NULL;
	}

	return rz_strbuf_drain_nofree(&sb);
}
