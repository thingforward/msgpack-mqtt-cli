/*
 * The MIT License (MIT)
 *
 * Bases on msgpack-tools/json2msgpack, copyright (c) 2015-2017 Nicholas Fraser
 */


#include <stdio.h>
#include <unistd.h>


#include <errno.h>
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "mpack/mpack.h"

#include "mosquitto/mosquitto.h"

using namespace rapidjson;

typedef struct options_t {
    const char* command;
    const char* runcmd;
    const char* out_filename;
    const char* in_filename;
    bool lax;
    bool use_float;
    bool base64_prefix;
    size_t base64_min_bytes;

    const char* mqtt_server_host;
    int mqtt_server_port;
    const char* mqtt_topic;
    bool debug;
} options_t;

// from json2msgpack.cpp
bool write_value(options_t* options, Value& value, mpack_writer_t* writer);
// from msgpack2json.cpp
template <class WriterType>
static bool element(mpack_reader_t* reader, WriterType& writer, bool b_base64, bool b_base64_prefix, bool b_debug);


static int convert_json_to_msgpack(options_t *options, Document &document, char *p_buf, size_t sz_buf) {
    mpack_writer_t writer;
    mpack_writer_init(&writer, p_buf, sz_buf);

    write_value(options, document, &writer);

    size_t len = writer.used;
    mpack_error_t error = mpack_writer_destroy(&writer);
    if (error != mpack_ok) {
        fprintf(stderr, "%s: error writing MessagePack: %s (%i)\n", options->command,
                mpack_error_to_string(error), (int)error);
        return -1;
    }
    return len;
}

static bool load_file_or_stdin(options_t *options, char **out_data, size_t *out_size) {
    FILE* in_file;
    if (options->in_filename) {
        in_file = fopen(options->in_filename, "rb");
        if (in_file == NULL) {
            fprintf(stderr, "%s: could not open \"%s\" for reading.\n", options->command, options->in_filename);
            return false;
        }
    } else {
        in_file = stdin;
    }

    size_t capacity = 4096;
    size_t size = 0;
    char* data = (char*)malloc(capacity);

    while (1) {
        size_t n = fread(data + size, 1, capacity - size, in_file);

        // RapidJSON in-situ requires a null-terminated string, so we need to scan the
        // data to make sure it has no null bytes. They are not legal JSON anyway.
        for (size_t i = size; i < size + n; ++i) {
            if (data[i] == '\0') {
                fprintf(stderr, "%s: JSON cannot contain null bytes\n", options->command);
                if (in_file != stdin)
                    fclose(in_file);
                free(data);
                return false;
            }
        }

        size += n;

        if (ferror(in_file)) {
            fprintf(stderr, "%s: error reading data\n", options->command);
            if (in_file != stdin)
                fclose(in_file);
            free(data);
            return false;
        }

        // We always need enough space to store the null-terminator
        if (size == capacity) {
            capacity *= 2;
            data = (char*)realloc(data, capacity);
        }

        if (feof(in_file))
            break;

        // This shouldn't happen; no bytes should mean error or EOF. We
        // check and throw an error anyway to avoid an infinite loop.
        if (n == 0) {
            fprintf(stderr, "%s: error reading data\n", options->command);
            if (in_file != stdin)
                fclose(in_file);
            free(data);
            return false;
        }
    }

    data[size] = '\0';

    fclose(in_file);
    *out_data = data;
    *out_size = size;
    return true;
}

void mqtt_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	printf("connect callback, rc=%d\n", result);
}

int mqtt_publish(options_t *options, char *p_buf, size_t sz_buf)
{
	uint8_t reconnect = true;
	char clientid[24];
	struct mosquitto *mosq;
	int rc = 0;

	mosquitto_lib_init();

	memset(clientid, 0, sizeof(clientid));
	snprintf(clientid, sizeof(clientid)-1, "msgpack-mqtt-cli/%d", getpid());
	mosq = mosquitto_new(clientid, true, 0);

	if(mosq){
    mosquitto_connect_callback_set(mosq, mqtt_connect_callback);

    if ( options->debug) {
      fprintf(stderr, "Connecting MQTT\n");
    }
  	rc = mosquitto_connect(mosq, options->mqtt_server_host, options->mqtt_server_port, 5);
    if ( rc != 0) {
      fprintf(stderr, "ERROR connecting to MQTT server at %s:%i\n", options->mqtt_server_host, options->mqtt_server_port);
    }

    if ( options->debug) {
      fprintf(stderr, "Connected, publishing to topic\n");
    }
		rc = mosquitto_publish(mosq, NULL, options->mqtt_topic, sz_buf, p_buf, 1, false);
    if ( rc != 0) {
      fprintf(stderr, "ERROR publishing to topic %s\n", options->mqtt_topic);
    }
    if ( options->debug) {
      fprintf(stderr, "Done.\n");
    }
		mosquitto_destroy(mosq);
	} else {
		fprintf(stderr, "Error creating mqtt client.\n");
	}

	mosquitto_lib_cleanup();

	return rc;
}

void mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
  options_t *options = (options_t*)obj;

  if ( options->debug) {
    fprintf(stderr, "Received message (mid=%i, len=%i)\n",
            message->mid,
            message->payloadlen
    );
  }
  // convert to msgpack

}

int mqtt_subscribe(options_t *options)
{
  uint8_t reconnect = true;
  char clientid[24];
  struct mosquitto *mosq;
  int rc = 0;

  mosquitto_lib_init();

  memset(clientid, 0, sizeof(clientid));
  snprintf(clientid, sizeof(clientid)-1, "msgpack-mqtt-cli/%d", getpid());
  mosq = mosquitto_new(clientid, true, options);

  if(mosq){
    mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
    mosquitto_message_callback_set(mosq, mqtt_message_callback);

    if ( options->debug) {
      fprintf(stderr, "Connecting MQTT\n");
    }
    rc = mosquitto_connect(mosq, options->mqtt_server_host, options->mqtt_server_port, 5);
    if ( rc != 0) {
      fprintf(stderr, "ERROR connecting to MQTT server at %s:%i\n", options->mqtt_server_host, options->mqtt_server_port);
    }

    if ( options->debug) {
      fprintf(stderr, "Connected, subscribing to topic %s\n", options->mqtt_topic);
    }
    rc = mosquitto_subscribe(mosq, NULL, options->mqtt_topic, 1);
    if ( rc != 0) {
      fprintf(stderr, "ERROR subscribing to topic %s\n", options->mqtt_topic);
    }
    // TODO: timeout via options_t
    rc = mosquitto_loop_forever(mosq, -1, 1);
    mosquitto_destroy(mosq);
  } else {
    fprintf(stderr, "Error creating mqtt client.\n");
  }

  mosquitto_lib_cleanup();

  return rc;
}



static bool process_pub(options_t *options) {
    char* data = NULL;
    size_t size = 0;

    if ( options->debug) {
      fprintf(stderr, "PUB: Reading input...\n");
    }

    if (!load_file_or_stdin(options, &data, &size))
        return false;

    // The data has been null-terminated by load_file()
    if ( options->debug) {
      fprintf(stderr, "PUB Converting JSON to Msgpack\n");
    }

    Document document;
    if (options->lax)
        document.ParseInsitu<kParseFullPrecisionFlag | kParseCommentsFlag | kParseTrailingCommasFlag>(data);
    else
        document.ParseInsitu<kParseFullPrecisionFlag>(data);

    if (document.HasParseError()) {
        fprintf(stderr, "PUB: %s: error parsing JSON at offset %i:\n    %s\n", options->command,
                (int)document.GetErrorOffset(), GetParseError_En(document.GetParseError()));
        free(data);
        return false;
    }

    char buf[1024];
    int len = convert_json_to_msgpack(options, document, buf, sizeof(buf));
    if ( len >= 0) {
      if ( options->debug) {
        fprintf(stderr, "PUB: Publishing on topic %s\n", options->mqtt_topic);
      }
      mqtt_publish(options, buf, len);
    }
    free(data);
    return true;
}

static bool process_sub(options_t *options) {
  mqtt_subscribe(options);
  return false;
}

static bool process(options_t *options) {
  if (strcmp("pub", options->runcmd) == 0) {
    return process_pub(options);
  }
  if (strcmp("sub", options->runcmd) == 0) {
    return process_sub(options);
  }
  return false;
}


static void parse_min_bytes(options_t* options) {
    const char* arg = optarg;
    char* end;
    errno = 0;
    int64_t value = strtol(arg, &end, 10);
    if (errno != 0 || *end != '\0' || value <= 0) {
        fprintf(stderr, "%s: -B requires a positive integer, not \"%s\"\n", options->command, arg);
        exit(EXIT_FAILURE);
    }
    if (SIZE_MAX < INT64_MAX && value > (int64_t)SIZE_MAX) {
        fprintf(stderr, "%s: -B argument is out of bounds: %" PRIi64 "\n", options->command, value);
        exit(EXIT_FAILURE);
    }
    options->base64_min_bytes = (size_t)value;
}

static void usage(const char* command) {
    fprintf(stderr, "Usage: %s COMMAND [-s <host|ip>] [-p <port>] [-t <topic>] [-i <infile>] [-o <outfile>] [-lfb] [-B <min>] [-d]\n", command);
    fprintf(stderr, "where:\n");
    fprintf(stderr, "COMMAND is one of\n");
    fprintf(stderr, "    pub           read from stdin or file, convert to msgpack, publish to topic\n");
    fprintf(stderr, "    sub           subscribe to topic, read and convert from msgpack to json, write to stdout or file\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -s <host|ip>  Hostname or IP of MQTT server (default: localhost)\n");
    fprintf(stderr, "    -p <port>     Port of MQTT server (default: 1883)\n");
    fprintf(stderr, "    -t <topic>    Name of topic to publish on (default: slyft)\n");
    fprintf(stderr, "    -i <infile>   Input filename (default: stdin)\n");
    fprintf(stderr, "    -o <outfile>  Output filename (default: stdout)\n");
    fprintf(stderr, "    -l  Lax mode, allows comments and trailing commas\n");
    fprintf(stderr, "    -f  Write floats instead of doubles\n");
    fprintf(stderr, "    -b  Convert base64 strings with \"base64:\" prefix to bin\n");
    fprintf(stderr, "    -d  Turn on debug output\n");
    fprintf(stderr, "    -B <min>  Try to convert any base64 string of at least <min> bytes to bin\n");
    fprintf(stderr, "    -h  Print this help\n");
}

#define OPTIONS_DEFAULT_MQTT_SERVER_HOST  "localhost"
#define OPTIONS_DEFAULT_MQTT_SERVER_PORT 1883
#define OPTIONS_DEFAULT_MQTT_TOPIC        "slyft"

int main(int argc, char** argv) {
    // clear and set default options
    options_t options;
    memset(&options, 0, sizeof(options));

    // check for command
    options.command = argv[0];
    if ( argc < 2) {
      usage(options.command);
      exit(1);
    }
    options.runcmd = argv[1];

    if (
            (strcmp("pub", options.runcmd) != 0) &&
            (strcmp("sub", options.runcmd) != 0)
            ) {
      fprintf(stderr, "command %s not valid, see usage\n", options.runcmd);
      exit(1);
    }

    argv++;
    argc--;

    options.mqtt_server_host = OPTIONS_DEFAULT_MQTT_SERVER_HOST;
    options.mqtt_server_port = OPTIONS_DEFAULT_MQTT_SERVER_PORT;
    options.mqtt_topic = OPTIONS_DEFAULT_MQTT_TOPIC;

    // parse options
    opterr = 0;
    int opt;
    while ((opt = getopt(argc, argv, "s:t:p:i:o:lfbdB:hv?")) != -1) {
        switch (opt) {
            case 's':
                options.mqtt_server_host = optarg;
                break;
            case 'p':
                options.mqtt_server_port = atoi(optarg);
                break;
            case 't':
                options.mqtt_topic = optarg;
                break;
            case 'i':
                options.in_filename = optarg;
                break;
            case 'o':
                options.out_filename = optarg;
                break;
            case 'l':
                options.lax = true;
                break;
            case 'f':
                options.use_float = true;
                break;
            case 'b':
                options.base64_prefix = true;
                break;
            case 'd':
                options.debug = true;
                break;
            case 'B':
                parse_min_bytes(&options);
                break;
            case 'h':
                usage(options.command);
                return EXIT_SUCCESS;
            default: /* ? */
                if (optopt == 0) {
                    // we allow both -h and -? as help
                    usage(options.command);
                    return EXIT_SUCCESS;
                }
                if (optopt == 'i' || optopt == 'o' || optopt == 'B')
                    fprintf(stderr, "%s: -%c requires an argument\n", options.command, optopt);
                else
                    fprintf(stderr, "%s: invalid option -- '%c'\n", options.command, optopt);
                usage(options.command);
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "%s: not an option -- \"%s\"\n", options.command, argv[optind]);
        usage(options.command);
        return EXIT_FAILURE;
    }

    return process(&options) ? EXIT_SUCCESS : EXIT_FAILURE;
}
