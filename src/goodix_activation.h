/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GOODIX_ACTIVATION_CONFIG_SIZE 256

typedef struct GoodixActivation GoodixActivation;

typedef enum {
    GOODIX_ACTIVATION_START_RECEIVE = 0,
    GOODIX_ACTIVATION_NOP,
    GOODIX_ACTIVATION_ENABLE_CHIP,
    GOODIX_ACTIVATION_QUERY_FIRMWARE,
    GOODIX_ACTIVATION_READ_PSK_STATUS,
    GOODIX_ACTIVATION_WRITE_PSK,
    GOODIX_ACTIVATION_QUERY_IAP,
    GOODIX_ACTIVATION_RESET_SENSOR,
    GOODIX_ACTIVATION_READ_SENSOR_ID,
    GOODIX_ACTIVATION_READ_OTP,
    GOODIX_ACTIVATION_BUILD_CONFIG,
    GOODIX_ACTIVATION_MCU_IDLE,
    GOODIX_ACTIVATION_UPLOAD_CONFIG,
    GOODIX_ACTIVATION_REQUEST_TLS,
    GOODIX_ACTIVATION_EXCHANGE_TLS,
    GOODIX_ACTIVATION_WAIT_TLS_QUIET,
    GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED,
    GOODIX_ACTIVATION_STOP_IO,
    GOODIX_ACTIVATION_CLEAR_SECRETS,
} GoodixActivationActionKind;

typedef enum {
    GOODIX_ACTIVATION_CONFIG_BEFORE_TLS = 0,
    GOODIX_ACTIVATION_CONFIG_AFTER_TLS,
} GoodixActivationConfigOrder;

typedef enum {
    GOODIX_ACTIVATION_EVENT_SUCCEEDED = 0,
    GOODIX_ACTIVATION_EVENT_TIMED_OUT,
    GOODIX_ACTIVATION_EVENT_IO_FAILED,
    GOODIX_ACTIVATION_EVENT_CANCELLED,
} GoodixActivationEvent;

typedef enum {
    GOODIX_ACTIVATION_PENDING = 0,
    GOODIX_ACTIVATION_ACTIVATED,
    GOODIX_ACTIVATION_UNSUPPORTED_FIRMWARE,
    GOODIX_ACTIVATION_TIMED_OUT,
    GOODIX_ACTIVATION_IO_FAILED,
    GOODIX_ACTIVATION_CANCELLED,
    GOODIX_ACTIVATION_DEACTIVATED,
} GoodixActivationOutcome;

typedef enum {
    GOODIX_ACTIVATION_OK = 0,
    GOODIX_ACTIVATION_INVALID_ARGUMENT,
    GOODIX_ACTIVATION_INVALID_PROFILE,
    GOODIX_ACTIVATION_INVALID_EVENT,
} GoodixActivationResult;

typedef struct {
    bool enable_chip_before_firmware;
    bool second_nop;
    uint32_t command_timeout_ms;
    uint32_t nop_timeout_ms;
} GoodixActivationDiscovery;

/* Strings and configuration bytes remain owned by the caller. */
typedef struct {
    const char *firmware;
    bool runtime_configuration;
    bool post_reset_nop;
    bool query_iap;
    bool read_sensor_id;
    bool read_otp;
    bool enable_chip_after_reset;
    bool enter_mcu_idle;
    GoodixActivationConfigOrder config_order;
    bool notify_tls_established;
    uint32_t command_timeout_ms;
    uint32_t tls_timeout_ms;
    uint32_t tls_quiet_ms;
    const uint8_t *configuration;
    size_t configuration_length;
} GoodixActivationProfile;

typedef struct {
    GoodixActivationActionKind kind;
    uint32_t timeout_ms;
    uint32_t wait_ms;
    const uint8_t *configuration;
    size_t configuration_length;
} GoodixActivationAction;

GoodixActivationResult goodix_activation_new(
    const GoodixActivationDiscovery *discovery,
    const GoodixActivationProfile *profiles,
    size_t profile_count,
    GoodixActivation **activation);

void goodix_activation_free(GoodixActivation *activation);

bool goodix_activation_current(const GoodixActivation *activation,
                               GoodixActivationAction *action);

/* firmware is required only when QUERY_FIRMWARE succeeds. */
GoodixActivationResult goodix_activation_advance(
    GoodixActivation *activation,
    GoodixActivationEvent event,
    const char *firmware);

GoodixActivationOutcome goodix_activation_outcome(
    const GoodixActivation *activation);

bool goodix_activation_action_command(GoodixActivationActionKind action,
                                      uint8_t *command);


/* Runtime profiles start without configuration. Only BUILD_CONFIG may supply
 * a checked configuration; the planner owns and wipes its copy. */
GoodixActivationResult goodix_activation_set_configuration(
    GoodixActivation *activation, const uint8_t *configuration, size_t length);

/* Required while READ_PSK_STATUS is current. A community write is skipped
 * when needed is false (hash already matches, or a private pairing key). */
GoodixActivationResult goodix_activation_set_community_psk_write(
    GoodixActivation *activation, bool needed);

/* Idle is a transient, ACK-only command; completion then drains I/O and wipes
 * secrets. Failure/cancel skips further device commands and still cleans up. */
GoodixActivationResult goodix_activation_deactivate(GoodixActivation *activation);

GoodixActivationProfile goodix_activation_profile_55b4(void);

/* After the TLS-established ACK, a deferred cancellation may enter idle
 * without uploading configuration. Only valid at NOTIFY_TLS_ESTABLISHED. */
GoodixActivationResult goodix_activation_cancel_after_tls(GoodixActivation *activation);
