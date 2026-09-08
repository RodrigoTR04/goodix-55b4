/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Probe for Goodix 27c6:55b4 fingerprint readers.
 *
 * This does not upload firmware or enter capture mode. Default commands are
 * read-only. Community PSK write happens in session activation, not here.
 * The optional sensor reset changes volatile state only.
 *
 * The wire format is reconstructed from the Goodix 55x4 work in libfprint and
 * goodix-fp-dump. Keep this program small and easy to audit before extending
 * it with any command that changes device state.
 */

#define _GNU_SOURCE

#include "goodix_command.h"
#include "goodix_psk.h"
#include "goodix_protocol.h"
#include "goodix_tls.h"
#include "goodix_key.h"
#include "goodix_security.h"

#include <libusb-1.0/libusb.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define GOODIX_VID 0x27c6
#define GOODIX_PID 0x55b4
#define GOODIX_INTERFACE 0
#define GOODIX_EP_OUT 0x01
#define GOODIX_EP_IN 0x82
#define GOODIX_READ_BUFFER 0x10000
#define GOODIX_TIMEOUT_MS 5000
#define GOODIX_DRAIN_TIMEOUT_MS 100
#define GOODIX_READER_TIMEOUT_MS 100

#define GOODIX_CMD_NOP 0x00
#define GOODIX_CMD_READ_SENSOR_REGISTER 0x82
#define GOODIX_CMD_FIRMWARE_VERSION 0xa8
#define GOODIX_CMD_READ_OTP 0xa6
#define GOODIX_CMD_RESET 0xa2
#define GOODIX_CMD_GET_IAP_VERSION 0xf6
#define GOODIX_CMD_PRESET_PSK_READ 0xe4
#define GOODIX_CMD_REQUEST_TLS_CONNECTION 0xd0
#define GOODIX_CMD_TLS_ESTABLISHED 0xd4

static uint16_t
read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t
read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
print_hex(const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; i++)
        printf("%02x%s", data[i], i + 1 == length ? "" : " ");
    putchar('\n');
}

static int
usb_error(const char *operation, int rc)
{
    fprintf(stderr, "%s: %s (%d)\n", operation, libusb_error_name(rc), rc);
    return 1;
}

/*
 * Wake a runtime-suspended USB device using the standard, read-only USB
 * GET_STATUS request.  The reference PyUSB implementation does this before
 * claiming the Goodix interface; without it, this internal device can remain
 * suspended and simply never ACK a bulk command.
 */
static int
wake_device(libusb_device_handle *handle)
{
    uint8_t status[2] = {0, 0};
    int rc = libusb_control_transfer(
        handle,
        LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_STANDARD |
            LIBUSB_RECIPIENT_DEVICE,
        LIBUSB_REQUEST_GET_STATUS, 0, 0, status, sizeof(status),
        GOODIX_TIMEOUT_MS);

    if (rc < 0)
        return usb_error("USB GET_STATUS", rc);
    if (rc != (int)sizeof(status)) {
        fprintf(stderr, "short USB GET_STATUS response: %d bytes\n", rc);
        return 1;
    }
    return 0;
}

/* Match the reference setup: explicitly select configuration value 1. */
static int
ensure_configuration(libusb_device_handle *handle)
{
    int rc = libusb_set_configuration(handle, 1);
    if (rc != LIBUSB_SUCCESS)
        return usb_error("setting USB configuration 1", rc);
    return 0;
}

/* Discard any complete messages left in the device's input queue. */
static int
drain_input(libusb_device_handle *handle)
{
    uint8_t buffer[GOODIX_READ_BUFFER];

    for (;;) {
        int transferred = 0;
        int rc = libusb_bulk_transfer(handle, GOODIX_EP_IN, buffer,
                                      (int)sizeof(buffer), &transferred,
                                      GOODIX_DRAIN_TIMEOUT_MS);

        if (rc == LIBUSB_ERROR_TIMEOUT)
            return 0;
        if (rc != LIBUSB_SUCCESS)
            return usb_error("draining input", rc);
    }
}

/* Build and send one outer message containing an inner protocol command. */
static int
send_wire(libusb_device_handle *handle,
          const uint8_t *wire,
          size_t wire_length)
{
    if (wire_length == 0 ||
        wire_length % GOODIX_PROTOCOL_USB_BLOCK_SIZE != 0) {
        fprintf(stderr, "invalid padded wire length: %zu\n", wire_length);
        return 1;
    }

    for (size_t offset = 0; offset < wire_length;
         offset += GOODIX_PROTOCOL_USB_BLOCK_SIZE) {
        int transferred = 0;
        int rc = libusb_bulk_transfer(
            handle, GOODIX_EP_OUT, (unsigned char *)(wire + offset),
            GOODIX_PROTOCOL_USB_BLOCK_SIZE, &transferred, GOODIX_TIMEOUT_MS);
        if (rc != LIBUSB_SUCCESS)
            return usb_error("bulk write", rc);
        if (transferred != GOODIX_PROTOCOL_USB_BLOCK_SIZE) {
            fprintf(stderr, "short bulk write: %d of %d bytes\n", transferred,
                    GOODIX_PROTOCOL_USB_BLOCK_SIZE);
            return 1;
        }
    }
    return 0;
}

static int
send_outer(libusb_device_handle *handle,
           uint8_t flags,
           const uint8_t *payload,
           size_t payload_length)
{
    size_t wire_length = goodix_outer_wire_size(payload_length);
    if (wire_length == 0) {
        fprintf(stderr, "outer payload is too large\n");
        return 1;
    }

    uint8_t *wire = malloc(wire_length);
    if (wire == NULL) {
        perror("malloc");
        return 1;
    }

    GoodixProtocolResult result = goodix_protocol_build_outer(
        flags, payload, payload_length, wire, wire_length, &wire_length);
    if (result != GOODIX_PROTOCOL_OK) {
        fprintf(stderr, "building outer frame: %s\n",
                goodix_protocol_result_string(result));
        free(wire);
        return 1;
    }

    int failed = send_wire(handle, wire, wire_length);
    free(wire);
    return failed;
}

static int
send_command(libusb_device_handle *handle,
             uint8_t command,
             const uint8_t *payload,
             size_t payload_length,
             int use_checksum)
{
    size_t wire_length = goodix_protocol_wire_size(payload_length);
    if (wire_length == 0) {
        fprintf(stderr, "payload is too large\n");
        return 1;
    }

    uint8_t *wire = calloc(1, wire_length);

    if (wire == NULL) {
        perror("calloc");
        return 1;
    }

    GoodixProtocolResult protocol_result = goodix_protocol_build_command(
        command, payload, payload_length, use_checksum != 0, wire,
        wire_length, &wire_length);
    if (protocol_result != GOODIX_PROTOCOL_OK) {
        fprintf(stderr, "building protocol command: %s\n",
                goodix_protocol_result_string(protocol_result));
        free(wire);
        return 1;
    }

    int failed = send_wire(handle, wire, wire_length);
    free(wire);
    return failed;
}

struct queued_message {
    uint8_t *inner;
    size_t inner_length;
    uint8_t flags;
    struct queued_message *next;
};

struct reader {
    libusb_device_handle *handle;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct queued_message *head;
    struct queued_message *tail;
    int stop;
    int ready;
    int failed;
    char error[160];
};

static void
reader_set_error(struct reader *reader, const char *message)
{
    pthread_mutex_lock(&reader->mutex);
    if (!reader->stop && !reader->failed) {
        reader->failed = 1;
        snprintf(reader->error, sizeof(reader->error), "%s", message);
        pthread_cond_broadcast(&reader->condition);
    }
    pthread_mutex_unlock(&reader->mutex);
}

/* Keep an IN transfer queued continuously, as libfprint does. */
static void *
reader_thread_main(void *user_data)
{
    struct reader *reader = user_data;
    uint8_t buffer[GOODIX_READ_BUFFER];

    for (;;) {
        pthread_mutex_lock(&reader->mutex);
        int stop = reader->stop;
        if (!reader->ready) {
            reader->ready = 1;
            pthread_cond_broadcast(&reader->condition);
        }
        pthread_mutex_unlock(&reader->mutex);
        if (stop)
            break;

        int transferred = 0;
        int rc = libusb_bulk_transfer(reader->handle, GOODIX_EP_IN, buffer,
                                      (int)sizeof(buffer), &transferred,
                                      GOODIX_READER_TIMEOUT_MS);
        if (rc == LIBUSB_ERROR_TIMEOUT)
            continue;
        if (rc != LIBUSB_SUCCESS) {
            char message[160];
            snprintf(message, sizeof(message), "bulk read: %s (%d)",
                     libusb_error_name(rc), rc);
            reader_set_error(reader, message);
            break;
        }

        GoodixOuterFrame frame;
        GoodixProtocolResult protocol_result = goodix_protocol_parse_outer(
            buffer, (size_t)transferred, &frame);
        if (protocol_result != GOODIX_PROTOCOL_OK) {
            char message[160];
            snprintf(message, sizeof(message), "malformed outer message: %s",
                     goodix_protocol_result_string(protocol_result));
            reader_set_error(reader, message);
            break;
        }

        struct queued_message *message = calloc(1, sizeof(*message));
        if (message == NULL) {
            reader_set_error(reader, "out of memory allocating message");
            break;
        }
        message->inner = malloc(frame.length == 0 ? 1 : frame.length);
        if (message->inner == NULL) {
            free(message);
            reader_set_error(reader, "out of memory allocating message data");
            break;
        }
        memcpy(message->inner, frame.data, frame.length);
        message->inner_length = frame.length;
        message->flags = frame.flags;

        pthread_mutex_lock(&reader->mutex);
        if (reader->stop) {
            pthread_mutex_unlock(&reader->mutex);
            free(message->inner);
            free(message);
            break;
        }
        if (reader->tail == NULL)
            reader->head = message;
        else
            reader->tail->next = message;
        reader->tail = message;
        pthread_cond_signal(&reader->condition);
        pthread_mutex_unlock(&reader->mutex);
    }

    return NULL;
}

static void reader_free_queue(struct reader *reader);

static int
reader_start(struct reader *reader, libusb_device_handle *handle)
{
    memset(reader, 0, sizeof(*reader));
    reader->handle = handle;

    int rc = pthread_mutex_init(&reader->mutex, NULL);
    if (rc != 0) {
        fprintf(stderr, "pthread_mutex_init: %s\n", strerror(rc));
        return 1;
    }
    rc = pthread_cond_init(&reader->condition, NULL);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_init: %s\n", strerror(rc));
        pthread_mutex_destroy(&reader->mutex);
        return 1;
    }
    rc = pthread_create(&reader->thread, NULL, reader_thread_main, reader);
    if (rc != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc));
        pthread_cond_destroy(&reader->condition);
        pthread_mutex_destroy(&reader->mutex);
        return 1;
    }

    /* Do not send the first command until the reader thread is running. */
    pthread_mutex_lock(&reader->mutex);
    while (!reader->ready && !reader->failed)
        pthread_cond_wait(&reader->condition, &reader->mutex);
    int failed = reader->failed;
    pthread_mutex_unlock(&reader->mutex);
    if (failed) {
        pthread_join(reader->thread, NULL);
        reader_free_queue(reader);
        pthread_cond_destroy(&reader->condition);
        pthread_mutex_destroy(&reader->mutex);
        return 1;
    }
    return 0;
}

static void
reader_free_queue(struct reader *reader)
{
    struct queued_message *message = reader->head;
    while (message != NULL) {
        struct queued_message *next = message->next;
        free(message->inner);
        free(message);
        message = next;
    }
    reader->head = NULL;
    reader->tail = NULL;
}

static void
reader_stop(struct reader *reader)
{
    pthread_mutex_lock(&reader->mutex);
    reader->stop = 1;
    pthread_cond_broadcast(&reader->condition);
    pthread_mutex_unlock(&reader->mutex);

    /* The reader's short timeout bounds how long join can take. */
    pthread_join(reader->thread, NULL);
    reader_free_queue(reader);
    pthread_cond_destroy(&reader->condition);
    pthread_mutex_destroy(&reader->mutex);
}

static void
add_milliseconds(struct timespec *deadline, unsigned milliseconds)
{
    deadline->tv_sec += milliseconds / 1000;
    deadline->tv_nsec += (long)(milliseconds % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

static int
reader_wait_message(struct reader *reader,
                    uint8_t *inner,
                    size_t inner_capacity,
                    size_t *inner_length,
                    uint8_t *flags,
                    unsigned timeout_ms,
                    int quiet_timeout)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        perror("clock_gettime");
        return 1;
    }
    add_milliseconds(&deadline, timeout_ms);

    pthread_mutex_lock(&reader->mutex);
    *inner_length = 0;
    for (;;) {
        if (reader->head != NULL) {
            struct queued_message *message = reader->head;
            reader->head = message->next;
            if (reader->head == NULL)
                reader->tail = NULL;
            pthread_mutex_unlock(&reader->mutex);

            if (message->inner_length > inner_capacity) {
                fprintf(stderr, "queued message is too large: %zu bytes\n",
                        message->inner_length);
                free(message->inner);
                free(message);
                return 1;
            }
            memcpy(inner, message->inner, message->inner_length);
            *inner_length = message->inner_length;
            *flags = message->flags;
            free(message->inner);
            free(message);
            return 0;
        }

        if (reader->failed) {
            fprintf(stderr, "reader: %s\n", reader->error);
            pthread_mutex_unlock(&reader->mutex);
            return 1;
        }

        int rc = pthread_cond_timedwait(&reader->condition, &reader->mutex,
                                        &deadline);
        if (rc == ETIMEDOUT) {
            if (!quiet_timeout)
                fprintf(stderr, "timed out waiting for device response\n");
            pthread_mutex_unlock(&reader->mutex);
            return quiet_timeout ? 0 : 1;
        }
        if (rc != 0) {
            fprintf(stderr, "pthread_cond_timedwait: %s\n", strerror(rc));
            pthread_mutex_unlock(&reader->mutex);
            return 1;
        }
    }
}

/* NOP is a queue-clearing housekeeping command; its response is optional. */
static int
run_nop(struct reader *reader)
{
    uint8_t inner[GOODIX_READ_BUFFER];
    size_t inner_length = 0;
    uint8_t flags = 0;

    if (send_command(reader->handle, GOODIX_CMD_NOP,
                     (const uint8_t[4]){0, 0, 0, 0}, 4, 0))
        return 1;

    /* Match goodix-fp-dump: give an optional ACK a short window, but do not
     * make its absence a probe failure. */
    if (reader_wait_message(reader, inner, sizeof(inner), &inner_length,
                            &flags, 100, 1))
        return 1;
    if (inner_length == 0)
        return 0;

    if (flags != GOODIX_PROTOCOL_FLAG) {
        fprintf(stderr, "unexpected NOP response flags: 0x%02x\n", flags);
        return 1;
    }

    GoodixProtocolMessage ack;
    GoodixProtocolResult protocol_result =
        goodix_protocol_parse_message(inner, inner_length, &ack);
    if (protocol_result == GOODIX_PROTOCOL_OK)
        protocol_result = goodix_protocol_expect_ack(&ack, GOODIX_CMD_NOP,
                                                     NULL);
    if (protocol_result != GOODIX_PROTOCOL_OK) {
        fprintf(stderr, "NOP response was not a valid ACK: %s\n",
                goodix_protocol_result_string(protocol_result));
        return 1;
    }

    return 0;
}

/* Send a command, validate its ACK, and optionally read its reply. */
static int
run_command(struct reader *reader,
            uint8_t command,
            const uint8_t *command_payload,
            size_t command_payload_length,
            int command_checksum,
            uint8_t reply_command,
            uint8_t *reply,
            size_t reply_capacity,
            size_t *reply_length)
{
    uint8_t inner[GOODIX_READ_BUFFER];
    bool expects_reply = reply_command != 0xff;
    GoodixCommand machine;

    if (expects_reply && (reply == NULL || reply_length == NULL)) {
        fprintf(stderr, "reply storage is required for command 0x%02x\n",
                command);
        return 1;
    }
    goodix_command_init(&machine, command, expects_reply, reply_command);

    if (send_command(reader->handle, command, command_payload,
                     command_payload_length, command_checksum))
        return 1;

    for (;;) {
        size_t inner_length = 0;
        uint8_t flags = 0;
        GoodixProtocolMessage response;

        if (reader_wait_message(reader, inner, sizeof(inner), &inner_length,
                                &flags, GOODIX_TIMEOUT_MS, 0))
            return 1;
        GoodixCommandResult result = goodix_command_feed(
            &machine, flags, inner, inner_length, &response);
        if (result == GOODIX_COMMAND_ACCEPTED)
            continue;
        if (result != GOODIX_COMMAND_FINISHED) {
            fprintf(stderr, "command 0x%02x failed: %s", command,
                    goodix_command_result_string(result));
            if (result == GOODIX_COMMAND_PROTOCOL_ERROR)
                fprintf(stderr, " (%s)", goodix_protocol_result_string(
                                              machine.protocol_error));
            fputc('\n', stderr);
            return 1;
        }

        if (!expects_reply) {
            if (reply_length != NULL)
                *reply_length = 0;
            return 0;
        }
        if (response.payload_length > reply_capacity) {
            fprintf(stderr, "reply is too large: %zu bytes\n",
                    response.payload_length);
            return 1;
        }
        memcpy(reply, response.payload, response.payload_length);
        *reply_length = response.payload_length;
        return 0;
    }
}

static int
read_psk_file(const char *path, uint8_t psk[GOODIX_TLS_PSK_SIZE])
{
    if (goodix_key_read(path, psk))
        return 0;
    fprintf(stderr, "PSK requires an absolute regular file, euid ownership, exact mode 0600 and 32 bytes\n");
    return 1;
}

static int
write_private_file_atomic(const char *path, const uint8_t *data, size_t length)
{
    if (path == NULL || path[0] != '/') {
        fprintf(stderr, "output path must be absolute\n");
        return 1;
    }

    size_t template_length = strlen(path) + sizeof(".tmp.XXXXXX");
    char *temporary_path = malloc(template_length);
    if (temporary_path == NULL) {
        perror("malloc");
        return 1;
    }
    snprintf(temporary_path, template_length, "%s.tmp.XXXXXX", path);

    int fd = mkstemp(temporary_path);
    if (fd < 0) {
        fprintf(stderr, "creating private temporary file: %s\n",
                strerror(errno));
        free(temporary_path);
        return 1;
    }

    int failed = 0;
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "setting private file permissions: %s\n",
                strerror(errno));
        failed = 1;
    }

    size_t offset = 0;
    while (!failed && offset < length) {
        ssize_t count = write(fd, data + offset, length - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            fprintf(stderr, "writing sealed blob: %s\n",
                    count < 0 ? strerror(errno) : "short write");
            failed = 1;
            break;
        }
        offset += (size_t)count;
    }

    if (!failed && fsync(fd) != 0) {
        fprintf(stderr, "syncing sealed blob: %s\n", strerror(errno));
        failed = 1;
    }
    if (close(fd) != 0 && !failed) {
        fprintf(stderr, "closing sealed blob: %s\n", strerror(errno));
        failed = 1;
    }

    if (!failed && link(temporary_path, path) != 0) {
        fprintf(stderr, "publishing sealed blob: %s\n", strerror(errno));
        failed = 1;
    }
    if (unlink(temporary_path) != 0 && !failed) {
        fprintf(stderr, "removing temporary file: %s\n", strerror(errno));
        failed = 1;
    }
    if (failed)
        unlink(temporary_path);
    free(temporary_path);
    return failed;
}

static void write_le32(uint8_t *p, uint32_t value);

static int
run_sealed_psk_read(struct reader *reader, const char *output_path)
{
    uint8_t sealed_blob[GOODIX_PSK_VENDOR_BLOB_SIZE] = {0};
    int failed = 1;

    for (size_t offset = 0; offset < sizeof(sealed_blob);) {
        size_t remaining = sizeof(sealed_blob) - offset;
        uint32_t requested_length = remaining > GOODIX_PSK_READ_CHUNK_SIZE
                                        ? GOODIX_PSK_READ_CHUNK_SIZE
                                        : (uint32_t)remaining;
        uint8_t request[GOODIX_PSK_READ_REQUEST_SIZE];
        uint8_t response[9 + GOODIX_PSK_READ_CHUNK_SIZE];
        size_t response_length = 0;

        GoodixPskResult psk_result = goodix_psk_build_read_request(
            requested_length, (uint32_t)offset, GOODIX_PSK_VENDOR_BLOB_TAG,
            request);
        if (psk_result != GOODIX_PSK_OK) {
            fprintf(stderr, "building sealed-blob request: %s\n",
                    goodix_psk_result_string(psk_result));
            goto out;
        }

        if (run_command(reader, GOODIX_CMD_PRESET_PSK_READ, request,
                        sizeof(request), 1, GOODIX_CMD_PRESET_PSK_READ,
                        response, sizeof(response), &response_length))
            goto out;

        GoodixPskChunk chunk;
        psk_result = goodix_psk_parse_read_response(
            response, response_length, GOODIX_PSK_VENDOR_BLOB_TAG,
            requested_length, &chunk);
        if (offset == 0 && psk_result == GOODIX_PSK_INVALID_LENGTH) {
            uint8_t direct_request[8] = {0};
            uint8_t direct_response[GOODIX_PSK_READ_RESPONSE_HEADER_SIZE +
                                    GOODIX_PSK_VENDOR_BLOB_SIZE];
            size_t direct_response_length = 0;

            printf("sealed_psk_blob: chunked read unavailable; trying "
                   "bounded direct read\n");
            write_le32(direct_request, GOODIX_PSK_VENDOR_BLOB_TAG);
            if (run_command(reader, GOODIX_CMD_PRESET_PSK_READ,
                            direct_request, sizeof(direct_request), 1,
                            GOODIX_CMD_PRESET_PSK_READ, direct_response,
                            sizeof(direct_response),
                            &direct_response_length))
                goto out;
            psk_result = goodix_psk_parse_read_response(
                direct_response, direct_response_length,
                GOODIX_PSK_VENDOR_BLOB_TAG, GOODIX_PSK_VENDOR_BLOB_SIZE,
                &chunk);
            if (psk_result != GOODIX_PSK_OK) {
                fprintf(stderr,
                        "validating direct sealed-blob response: %s "
                        "(%zu bytes received, %zu expected)\n",
                        goodix_psk_result_string(psk_result),
                        direct_response_length, sizeof(direct_response));
                goto out;
            }
            memcpy(sealed_blob, chunk.data, chunk.length);
            break;
        }
        if (psk_result != GOODIX_PSK_OK) {
            fprintf(stderr,
                    "validating sealed-blob response at offset %zu: %s "
                    "(%zu bytes received, %zu expected)\n",
                    offset, goodix_psk_result_string(psk_result),
                    response_length,
                    GOODIX_PSK_READ_RESPONSE_HEADER_SIZE +
                        (size_t)requested_length);
            goto out;
        }
        memcpy(sealed_blob + offset, chunk.data, chunk.length);
        offset += chunk.length;
    }

    if (!goodix_psk_is_canonical_dpapi_blob(sealed_blob,
                                             sizeof(sealed_blob))) {
        fprintf(stderr,
                "sensor data is not a canonical 324-byte DPAPI blob\n");
        goto out;
    }
    if (write_private_file_atomic(output_path, sealed_blob,
                                  sizeof(sealed_blob)))
        goto out;

    printf("sealed_psk_blob: saved privately (%zu bytes)\n",
           sizeof(sealed_blob));
    failed = 0;

out:
    explicit_bzero(sealed_blob, sizeof(sealed_blob));
    return failed;
}

static int
wait_for_ack(struct reader *reader, uint8_t command)
{
    uint8_t inner[GOODIX_READ_BUFFER];
    size_t inner_length = 0;
    uint8_t flags = 0;

    if (reader_wait_message(reader, inner, sizeof(inner), &inner_length,
                            &flags, GOODIX_TIMEOUT_MS, 0))
        return 1;
    if (flags != GOODIX_PROTOCOL_FLAG) {
        fprintf(stderr, "unexpected ACK outer flags: 0x%02x\n", flags);
        return 1;
    }

    GoodixProtocolMessage ack;
    GoodixProtocolResult result =
        goodix_protocol_parse_message(inner, inner_length, &ack);
    if (result == GOODIX_PROTOCOL_OK)
        result = goodix_protocol_expect_ack(&ack, command, NULL);
    if (result != GOODIX_PROTOCOL_OK) {
        fprintf(stderr, "command 0x%02x was not ACKed: %s\n", command,
                goodix_protocol_result_string(result));
        return 1;
    }
    return 0;
}

static int
run_tls_session_check(struct reader *reader, const char *psk_path)
{
    uint8_t psk[GOODIX_TLS_PSK_SIZE];
    GoodixTlsSession *session = NULL;
    int failed = 1;

    if (read_psk_file(psk_path, psk))
        return 1;
    GoodixTlsResult tls_result =
        goodix_tls_session_new(psk, sizeof(psk), &session);
    explicit_bzero(psk, sizeof(psk));
    if (tls_result != GOODIX_TLS_OK) {
        fprintf(stderr, "creating TLS session: %s\n",
                goodix_tls_result_string(tls_result));
        return 1;
    }

    const uint8_t empty_payload[2] = {0, 0};
    if (send_command(reader->handle, GOODIX_CMD_REQUEST_TLS_CONNECTION,
                     empty_payload, sizeof(empty_payload), 1) ||
        wait_for_ack(reader, GOODIX_CMD_REQUEST_TLS_CONNECTION))
        goto out;

    for (unsigned flight = 0; flight < 16; flight++) {
        uint8_t tls_input[GOODIX_READ_BUFFER];
        size_t tls_input_length = 0;
        uint8_t flags = 0;

        if (reader_wait_message(reader, tls_input, sizeof(tls_input),
                                &tls_input_length, &flags, GOODIX_TIMEOUT_MS,
                                0))
            goto out;
        if (flags != GOODIX_TLS_FLAG) {
            fprintf(stderr,
                    "unexpected TLS handshake outer flags: 0x%02x\n", flags);
            goto out;
        }

        tls_result = goodix_tls_session_feed(session, tls_input,
                                             tls_input_length);
        if (tls_result != GOODIX_TLS_WANT_INPUT &&
            tls_result != GOODIX_TLS_ESTABLISHED &&
            tls_result != GOODIX_TLS_OK) {
            fprintf(stderr, "TLS handshake: %s\n",
                    goodix_tls_result_string(tls_result));
            goto out;
        }

        size_t output_length = goodix_tls_session_pending_output(session);
        if (output_length != 0) {
            uint8_t *output = malloc(output_length);
            if (output == NULL) {
                perror("malloc");
                goto out;
            }
            tls_result = goodix_tls_session_take_output(
                session, output, output_length, &output_length);
            if (tls_result != GOODIX_TLS_OK ||
                send_outer(reader->handle, GOODIX_TLS_FLAG, output,
                           output_length)) {
                if (tls_result != GOODIX_TLS_OK)
                    fprintf(stderr, "reading TLS output: %s\n",
                            goodix_tls_result_string(tls_result));
                free(output);
                goto out;
            }
            free(output);
        }

        if (goodix_tls_session_is_established(session)) {
            const struct timespec quiet_time = {.tv_sec = 0,
                                                .tv_nsec = 15000000L};
            if (nanosleep(&quiet_time, NULL) != 0) {
                perror("nanosleep");
                goto out;
            }
            if (run_command(reader, GOODIX_CMD_TLS_ESTABLISHED, empty_payload,
                            sizeof(empty_payload), 1, 0xff, NULL, 0, NULL))
                goto out;
            printf("tls_session: established\n");
            failed = 0;
            goto out;
        }
    }

    fprintf(stderr, "TLS handshake exceeded 16 flights\n");

out:
    goodix_tls_session_free(session);
    return failed;
}

/* Reset the sensing element, following the known GF3208 initialization flow. */
static int
run_sensor_reset(struct reader *reader)
{
    /* bit 0: reset sensor; bit 1: soft-reset MCU; bits 2..7: 1. */
    const uint8_t payload[2] = {0x05, 20};
    uint8_t reply[GOODIX_READ_BUFFER];
    size_t reply_length = 0;

    if (run_command(reader, GOODIX_CMD_RESET, payload, sizeof(payload), 1,
                    GOODIX_CMD_RESET, reply, sizeof(reply), &reply_length))
        return 1;

    printf("reset_raw: ");
    print_hex(reply, reply_length);
    if (reply_length < 3 || reply[0] != 0x01) {
        fprintf(stderr, "unexpected sensor reset response\n");
        return 1;
    }
    printf("reset_number: %u\n", read_le16(reply + 1));
    return 0;
}

static void
write_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value & 0xffU);
    p[1] = (uint8_t)((value >> 8) & 0xffU);
    p[2] = (uint8_t)((value >> 16) & 0xffU);
    p[3] = (uint8_t)((value >> 24) & 0xffU);
}

/* Read the bootloader/IAP version without entering or modifying IAP mode. */
static int
run_iap_version(struct reader *reader)
{
    const uint8_t payload[2] = {25, 0};
    uint8_t reply[GOODIX_READ_BUFFER];
    size_t reply_length = 0;

    if (run_command(reader, GOODIX_CMD_GET_IAP_VERSION, payload,
                    sizeof(payload), 1, GOODIX_CMD_GET_IAP_VERSION, reply,
                    sizeof(reply), &reply_length))
        return 1;

    size_t text_length = strnlen((const char *)reply, reply_length);
    printf("iap_version: %.*s\n", (int)text_length, (const char *)reply);
    printf("iap_version_raw: ");
    print_hex(reply, reply_length);
    return 0;
}

/* Read provisioning metadata without returning the PSK-derived hash itself. */
static int
run_psk_status(struct reader *reader)
{
    const uint32_t requested_flags = UINT32_C(0xbb020007);
    uint8_t payload[8] = {0};
    uint8_t reply[GOODIX_READ_BUFFER];
    size_t reply_length = 0;

    write_le32(payload, requested_flags);
    if (run_command(reader, GOODIX_CMD_PRESET_PSK_READ, payload,
                    sizeof(payload), 1, GOODIX_CMD_PRESET_PSK_READ, reply,
                    sizeof(reply), &reply_length))
        return 1;

    if (reply_length < 9) {
        fprintf(stderr, "PSK status response is too short: %zu bytes\n",
                reply_length);
        return 1;
    }

    uint8_t status = reply[0];
    uint32_t flags = read_le32(reply + 1);
    uint32_t psk_length = read_le32(reply + 5);
    printf("psk_read_status: %s (0x%02x)\n",
           status == 0 ? "success" : "device-reported-failure", status);
    printf("psk_flags: 0x%08" PRIx32 "\n", flags);
    printf("psk_length: %" PRIu32 "\n", psk_length);

    if (status != 0)
        return 1;
    if ((uint64_t)psk_length > (uint64_t)(reply_length - 9)) {
        fprintf(stderr,
                "PSK status length exceeds response: %" PRIu32
                " bytes in %zu-byte reply\n",
                psk_length, reply_length);
        return 1;
    }

    int reference_match =
        psk_length == GOODIX_PSK_PMK_HASH_SIZE &&
        memcmp(reply + 9, goodix_psk_community_pmk_hash(),
               GOODIX_PSK_PMK_HASH_SIZE) == 0;
    printf("psk_hash: redacted (%" PRIu32 " bytes)\n", psk_length);
    printf("psk_hash_matches_reference: %s\n",
           reference_match ? "yes" : "no");
    return 0;
}

static void
usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--all] [--firmware] [--iap-version] [--psk-status] "
            "[--chip-id] [--otp] "
            "[--reset-sensor] [--read-sealed-psk OUTPUT_FILE] "
            "[--session-check PSK_FILE]\n"
            "\n"
            "Read-only probe for Goodix USB %04x:%04x.\n"
            "With no selection, firmware, IAP version, and redacted PSK "
            "status are read. OTP and chip-ID require --otp / --chip-id "
            "or --all.\n"
            "--iap-version reads the bootloader/IAP version without writing "
            "the device.\n"
            "--psk-status reads provisioning metadata; the hash is redacted.\n"
            "--read-sealed-psk reads vendor slot 0xbb010002 in bounded "
            "chunks and saves a validated DPAPI blob to a new private file.\n"
            "--reset-sensor explicitly performs a volatile sensor reset "
            "before register/OTP reads.\n"
            "--session-check performs a transient TLS handshake using an "
            "exactly 32-byte raw PSK file.\n"
            "The PSK is never printed or written to the device; the file "
            "must have exact mode 0600 and euid ownership.\n",
            program, GOODIX_VID, GOODIX_PID);
}

int
main(int argc, char **argv)
{
    if (!goodix_security_disable_dumps()) {
        fprintf(stderr, "Could not disable process dumps\n");
        return 1;
    }
    int do_firmware = 0;
    int do_iap_version = 0;
    int do_psk_status = 0;
    int do_chip_id = 0;
    int do_otp = 0;
    int do_reset_sensor = 0;
    const char *sealed_psk_output_path = NULL;
    const char *session_psk_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--all") == 0) {
            do_firmware = do_chip_id = do_otp = 1;
        } else if (strcmp(argv[i], "--firmware") == 0) {
            do_firmware = 1;
        } else if (strcmp(argv[i], "--iap-version") == 0) {
            do_iap_version = 1;
        } else if (strcmp(argv[i], "--psk-status") == 0) {
            do_psk_status = 1;
        } else if (strcmp(argv[i], "--chip-id") == 0) {
            do_chip_id = 1;
        } else if (strcmp(argv[i], "--otp") == 0) {
            do_otp = 1;
        } else if (strcmp(argv[i], "--reset-sensor") == 0) {
            do_reset_sensor = 1;
        } else if (strcmp(argv[i], "--read-sealed-psk") == 0) {
            if (i + 1 == argc) {
                usage(argv[0]);
                return 2;
            }
            sealed_psk_output_path = argv[++i];
        } else if (strcmp(argv[i], "--session-check") == 0) {
            if (i + 1 == argc) {
                usage(argv[0]);
                return 2;
            }
            session_psk_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!do_firmware && !do_iap_version && !do_psk_status && !do_chip_id &&
        !do_otp && sealed_psk_output_path == NULL &&
        session_psk_path == NULL)
        do_firmware = do_iap_version = do_psk_status = 1;

    if (sealed_psk_output_path != NULL) {
        struct stat output_stat;

        if (sealed_psk_output_path[0] != '/') {
            fprintf(stderr,
                    "sealed-blob output path must be absolute; choose a path "
                    "outside the repository\n");
            return 2;
        }
        if (lstat(sealed_psk_output_path, &output_stat) == 0) {
            fprintf(stderr, "sealed-blob output already exists\n");
            return 2;
        }
        if (errno != ENOENT) {
            fprintf(stderr, "checking sealed-blob output: %s\n",
                    strerror(errno));
            return 2;
        }
    }

    libusb_context *context = NULL;
    int rc = libusb_init(&context);
    if (rc != LIBUSB_SUCCESS)
        return usb_error("libusb initialization", rc);

    libusb_device_handle *handle =
        libusb_open_device_with_vid_pid(context, GOODIX_VID, GOODIX_PID);
    if (handle == NULL) {
        fprintf(stderr,
                "could not open Goodix %04x:%04x; run as root or add a "
                "scoped udev rule\n",
                GOODIX_VID, GOODIX_PID);
        libusb_exit(context);
        return 1;
    }

    if (wake_device(handle)) {
        libusb_close(handle);
        libusb_exit(context);
        return 1;
    }
    if (ensure_configuration(handle)) {
        libusb_close(handle);
        libusb_exit(context);
        return 1;
    }

    libusb_set_auto_detach_kernel_driver(handle, 1);
    rc = libusb_claim_interface(handle, GOODIX_INTERFACE);
    if (rc != LIBUSB_SUCCESS) {
        int result = usb_error("claiming interface", rc);
        libusb_close(handle);
        libusb_exit(context);
        return result;
    }

    int result = 0;
    struct reader reader;
    int reader_started = 0;
    uint8_t reply[GOODIX_READ_BUFFER];
    size_t reply_length = 0;

    /* NOP is the reference implementation's queue-clearing command. */
    fprintf(stderr, "probe: NOP\n");
    if (drain_input(handle)) {
        result = 1;
        goto out;
    }
    if (reader_start(&reader, handle)) {
        result = 1;
        goto out;
    }
    reader_started = 1;
    if (run_nop(&reader)) {
        result = 1;
        goto out;
    }

    if (do_firmware) {
        fprintf(stderr, "probe: firmware version\n");
        const uint8_t payload[2] = {0, 0};
        if (run_command(&reader, GOODIX_CMD_FIRMWARE_VERSION, payload,
                        sizeof(payload), 1, GOODIX_CMD_FIRMWARE_VERSION,
                        reply, sizeof(reply), &reply_length)) {
            result = 1;
            goto out;
        }

        size_t text_length = strnlen((const char *)reply, reply_length);
        printf("firmware: %.*s\n", (int)text_length, (const char *)reply);
        printf("firmware_raw: ");
        print_hex(reply, reply_length);
    }

    if (do_iap_version) {
        fprintf(stderr, "probe: IAP version\n");
        if (run_iap_version(&reader)) {
            result = 1;
            goto out;
        }
    }

    if (do_psk_status) {
        fprintf(stderr, "probe: PSK status (read-only)\n");
        if (run_psk_status(&reader)) {
            result = 1;
            goto out;
        }
    }

    if (sealed_psk_output_path != NULL) {
        fprintf(stderr, "probe: vendor sealed PSK blob (read-only)\n");
        if (run_sealed_psk_read(&reader, sealed_psk_output_path)) {
            result = 1;
            goto out;
        }
    }

    if (session_psk_path != NULL) {
        fprintf(stderr, "probe: transient TLS session check\n");
        if (run_tls_session_check(&reader, session_psk_path)) {
            result = 1;
            goto out;
        }
    }

    if (do_chip_id) {
        if (do_reset_sensor) {
            fprintf(stderr, "probe: sensor reset (explicit)\n");
            if (run_sensor_reset(&reader)) {
                result = 1;
                goto out;
            }
            /* The reference GF3208 flow sends NOP after reset as well. */
            if (run_nop(&reader)) {
                result = 1;
                goto out;
            }
        }
        fprintf(stderr, "probe: sensor chip-ID register\n");
        uint8_t payload[4] = {0, 0, 0, 4};
        if (run_command(&reader, GOODIX_CMD_READ_SENSOR_REGISTER, payload,
                        sizeof(payload), 1, GOODIX_CMD_READ_SENSOR_REGISTER,
                        reply, sizeof(reply), &reply_length)) {
            result = 1;
            goto out;
        }

        printf("chip_id_register_0x0000: ");
        print_hex(reply, reply_length);
    }

    if (do_otp) {
        if (do_reset_sensor && !do_chip_id) {
            fprintf(stderr, "probe: sensor reset (explicit)\n");
            if (run_sensor_reset(&reader)) {
                result = 1;
                goto out;
            }
            if (run_nop(&reader)) {
                result = 1;
                goto out;
            }
        }
        fprintf(stderr, "probe: OTP\n");
        const uint8_t payload[2] = {0, 0};
        if (run_command(&reader, GOODIX_CMD_READ_OTP, payload,
                        sizeof(payload), 1, GOODIX_CMD_READ_OTP, reply,
                        sizeof(reply), &reply_length)) {
            result = 1;
            goto out;
        }

        printf("otp: ");
        print_hex(reply, reply_length);
    }

out:
    if (reader_started)
        reader_stop(&reader);
    libusb_release_interface(handle, GOODIX_INTERFACE);
    libusb_close(handle);
    libusb_exit(context);
    return result;
}
