/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2017 Nicholas Fraser
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>

#include "mpack/mpack.h"
#include "rapidjson/error/en.h"

// libb64 doesn't have extern "C" around its C headers
extern "C" {
#include "b64/cdecode.h"
#include "b64/cencode.h"
}

#define BUFFER_SIZE 65536

#include <errno.h>
#include "rapidjson/document.h"

#include "mosquitto/mosquitto.h"

using namespace rapidjson;

typedef struct options_t {
    const char* command;
    const char* out_filename;
    const char* in_filename;
    bool lax;
    bool use_float;
    bool base64_prefix;
    size_t base64_min_bytes;
} options_t;

static const char* prefix_ext    = "ext:";
static const char* prefix_base64 = "base64:";

// libb64 doesn't have the means to return errors on invalid characters, so
// for base64 detection, we manually scan the string for invalid characters.
// For detection we allow CR/LF but we don't allow spaces (otherwise pretty
// much any normal string would be detected as base64.)
static bool is_base64(const char* string, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        char c = string[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '=' || c == '\r' || c == '\n')) {
            return false;
        }
    }
    return true;
}

static char* convert_base64(options_t* options, const char* p, size_t len, size_t* out_bytes) {
    size_t bytes = len * 3 / 4 + 4; // TODO check this
    char* data = (char*)malloc(bytes);
    if (!data) {
        fprintf(stderr, "%s: allocation failure\n", options->command);
        return NULL;
    }
    base64_decodestate state;
    base64_init_decodestate(&state);
    bytes = base64_decode_block(p, len, data, &state);
    *out_bytes = bytes;
    return data;
}

static bool write_string(options_t* options, mpack_writer_t* writer, const char* string, size_t length, bool allow_detection) {

    if (options->base64_prefix) {

        // check for base64 prefix
        if (length >= strlen(prefix_base64) && memcmp(string, prefix_base64, strlen(prefix_base64)) == 0) {
            const char* base64_data = string + strlen(prefix_base64);
            size_t base64_len = length - strlen(prefix_base64);
            if (!is_base64(base64_data, base64_len)) {
                fprintf(stderr, "%s: string prefixed with \"base64:\" contains invalid base64\n", options->command);
                return false;
            }

            // write base64
            size_t count;
            char* bytes = convert_base64(options, base64_data, base64_len, &count);
            if (bytes) {
                mpack_write_bin(writer, bytes, count);
                free(bytes);
                return mpack_writer_error(writer) == mpack_ok;
            }
            return false;
        }

        // check for ext prefix
        if (length >= strlen(prefix_ext) && memcmp(string, prefix_ext, strlen(prefix_ext)) == 0) {

            // parse exttype
            const char* exttype_str = string + strlen(prefix_ext);
            char* remainder;
            errno = 0;
            int64_t exttype = strtol(exttype_str, &remainder, 10);
            if (errno != 0 || *(remainder++) != ':' || strlen(remainder) < strlen(prefix_base64)
                    || memcmp(remainder, prefix_base64, strlen(prefix_base64)) != 0) {
                fprintf(stderr, "\"%s\"\n", remainder);
                fprintf(stderr, "%s: string prefixed with \"ext:\" contains invalid prefix\n", options->command);
                return false;
            }
            if (exttype < INT8_MIN || exttype > INT8_MAX) {
                fprintf(stderr, "%s: string prefixed with \"ext:\" has out-of-bounds ext type: %" PRIi64 "\n", options->command, exttype);
                return false;
            }

            // check base64
            const char* base64_data = remainder + strlen(prefix_base64);
            size_t base64_len = strlen(base64_data);
            if (!is_base64(base64_data, base64_len)) {
                fprintf(stderr, "\"%s\"\n", base64_data);
                fprintf(stderr, "%s: string prefixed with \"ext:\" contains invalid base64\n", options->command);
                return false;
            }

            // write ext
            size_t count;
            char* bytes = convert_base64(options, base64_data, base64_len, &count);
            if (bytes) {
                mpack_write_ext(writer, (int8_t)exttype, bytes, count);
                free(bytes);
                return mpack_writer_error(writer) == mpack_ok;
            }
            return false;
        }

    }

    // try to parse as base64
    if (allow_detection && options->base64_min_bytes != 0 && length >= options->base64_min_bytes && is_base64(string, length)) {
        size_t count;
        char* bytes = convert_base64(options, string, length, &count);
        if (bytes) {
            mpack_write_bin(writer, bytes, count);
            free(bytes);
            return mpack_writer_error(writer) == mpack_ok;
        }
        return false;
    }

    mpack_write_str(writer, string, length);
    return mpack_writer_error(writer) == mpack_ok;
}

bool write_value(options_t* options, Value& value, mpack_writer_t* writer) {
    switch (value.GetType()) {
        case kNullType:   mpack_write_nil(writer);    break;
        case kTrueType:   mpack_write_true(writer);   break;
        case kFalseType:  mpack_write_false(writer);  break;

        case kNumberType:
            if (value.IsDouble()) {
                if (options->use_float)
                    mpack_write_float(writer, (float)value.GetDouble());
                else
                    mpack_write_double(writer, value.GetDouble());
            } else if (value.IsUint64()) {
                mpack_write_u64(writer, value.GetUint64());
            } else {
                mpack_write_i64(writer, value.GetInt64());
            }
            break;

        case kStringType:
            if (!write_string(options, writer, value.GetString(), value.GetStringLength(), true))
                return false;
            break;

        case kArrayType: {
            mpack_start_array(writer, value.Size());
            Value::ValueIterator it = value.Begin(), end = value.End();
            for (; it != end; ++it) {
                if (!write_value(options, *it, writer))
                    return false;
            }
            mpack_finish_array(writer);
            break;
        }

        case kObjectType: {
            mpack_start_map(writer, value.MemberCount());
            Value::MemberIterator it = value.MemberBegin(), end = value.MemberEnd();
            for (; it != end; ++it) {
                if (!write_string(options, writer, it->name.GetString(), it->name.GetStringLength(), false))
                    return false;
                if (!write_value(options, it->value, writer))
                    return false;
            }
            mpack_finish_map(writer);
            break;
        }

        default:
            return false;
    }

    return mpack_writer_error(writer) == mpack_ok;
}
