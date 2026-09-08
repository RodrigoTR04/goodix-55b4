/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_activation.h"

#include <stdlib.h>
#include <string.h>

#define GOODIX_ACTIVATION_MAX_ACTIONS 24

typedef enum {
    PHASE_RUNNING = 0,
    PHASE_CLEANUP,
    PHASE_FINISHED,
} GoodixActivationPhase;

struct GoodixActivation {
    uint8_t configuration[GOODIX_ACTIVATION_CONFIG_SIZE];
    bool configuration_ready;
    bool deactivating;
    GoodixActivationOutcome idle_outcome;
    GoodixActivationDiscovery discovery;
    const GoodixActivationProfile *profiles;
    size_t profile_count;
    const GoodixActivationProfile *profile;
    GoodixActivationAction actions[GOODIX_ACTIVATION_MAX_ACTIONS];
    size_t action_count;
    size_t action_index;
    GoodixActivationPhase phase;
    GoodixActivationOutcome outcome;
    GoodixActivationOutcome cleanup_outcome;
    bool psk_decision_ready;
    bool psk_write_needed;
};

static bool
append_action(GoodixActivation *activation,
              GoodixActivationActionKind kind,
              uint32_t timeout_ms,
              uint32_t wait_ms,
              const uint8_t *configuration,
              size_t configuration_length)
{
    GoodixActivationAction *action;

    if (activation->action_count >= GOODIX_ACTIVATION_MAX_ACTIONS)
        return false;

    action = &activation->actions[activation->action_count++];
    action->kind = kind;
    action->timeout_ms = timeout_ms;
    action->wait_ms = wait_ms;
    action->configuration = configuration;
    action->configuration_length = configuration_length;
    return true;
}

static bool
valid_profile(const GoodixActivationDiscovery *discovery,
              const GoodixActivationProfile *profile)
{
    if (profile->firmware == NULL || profile->firmware[0] == '\0' ||
        profile->command_timeout_ms == 0 || profile->tls_timeout_ms == 0)
        return false;
    if (profile->runtime_configuration) {
        if (!profile->read_otp || profile->configuration != NULL ||
            profile->configuration_length != 0)
            return false;
    } else if (profile->configuration == NULL ||
               profile->configuration_length != GOODIX_ACTIVATION_CONFIG_SIZE) {
        return false;
    }
    if (profile->config_order != GOODIX_ACTIVATION_CONFIG_BEFORE_TLS &&
        profile->config_order != GOODIX_ACTIVATION_CONFIG_AFTER_TLS)
        return false;
    if (discovery->enable_chip_before_firmware &&
        profile->enable_chip_after_reset)
        return false;
    return true;
}

static bool
append_discovery(GoodixActivation *activation)
{
    uint32_t timeout = activation->discovery.command_timeout_ms;

    if (!append_action(activation,
                       GOODIX_ACTIVATION_START_RECEIVE,
                       0,
                       0,
                       NULL,
                       0) ||
        !append_action(activation,
                       GOODIX_ACTIVATION_NOP,
                       activation->discovery.nop_timeout_ms,
                       0,
                       NULL,
                       0))
        return false;

    if (activation->discovery.enable_chip_before_firmware &&
        !append_action(activation,
                       GOODIX_ACTIVATION_ENABLE_CHIP,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (activation->discovery.second_nop &&
        !append_action(activation,
                       GOODIX_ACTIVATION_NOP,
                       activation->discovery.nop_timeout_ms,
                       0,
                       NULL,
                       0))
        return false;

    return append_action(activation,
                         GOODIX_ACTIVATION_QUERY_FIRMWARE,
                         timeout,
                         0,
                         NULL,
                         0);
}

static bool
append_profile_actions(GoodixActivation *activation,
                       const GoodixActivationProfile *profile)
{
    uint32_t timeout = profile->command_timeout_ms;

    if (!append_action(activation,
                       GOODIX_ACTIVATION_READ_PSK_STATUS,
                       timeout,
                       0,
                       NULL,
                       0) ||
        !append_action(activation,
                       GOODIX_ACTIVATION_WRITE_PSK,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (profile->query_iap &&
        !append_action(activation,
                       GOODIX_ACTIVATION_QUERY_IAP,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (!append_action(activation,
                       GOODIX_ACTIVATION_RESET_SENSOR,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (profile->post_reset_nop &&
        !append_action(activation, GOODIX_ACTIVATION_NOP,
                       activation->discovery.nop_timeout_ms, 0, NULL, 0))
        return false;
    if (profile->read_sensor_id &&
        !append_action(activation,
                       GOODIX_ACTIVATION_READ_SENSOR_ID,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (profile->read_otp &&
        !append_action(activation,
                       GOODIX_ACTIVATION_READ_OTP,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (profile->runtime_configuration &&
        !append_action(activation, GOODIX_ACTIVATION_BUILD_CONFIG,
                       timeout, 0, NULL, 0))
        return false;
    if (profile->enable_chip_after_reset &&
        !append_action(activation,
                       GOODIX_ACTIVATION_ENABLE_CHIP,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;
    if (profile->enter_mcu_idle &&
        !append_action(activation,
                       GOODIX_ACTIVATION_MCU_IDLE,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;

    if (profile->config_order == GOODIX_ACTIVATION_CONFIG_BEFORE_TLS &&
        !append_action(activation,
                       GOODIX_ACTIVATION_UPLOAD_CONFIG,
                       timeout,
                       0,
                       profile->runtime_configuration ? activation->configuration :
                           profile->configuration,
                       GOODIX_ACTIVATION_CONFIG_SIZE))
        return false;

    if (!append_action(activation,
                       GOODIX_ACTIVATION_REQUEST_TLS,
                       timeout,
                       0,
                       NULL,
                       0) ||
        !append_action(activation,
                       GOODIX_ACTIVATION_EXCHANGE_TLS,
                       profile->tls_timeout_ms,
                       0,
                       NULL,
                       0))
        return false;

    if (profile->tls_quiet_ms > 0 &&
        !append_action(activation,
                       GOODIX_ACTIVATION_WAIT_TLS_QUIET,
                       0,
                       profile->tls_quiet_ms,
                       NULL,
                       0))
        return false;
    if (profile->notify_tls_established &&
        !append_action(activation,
                       GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED,
                       timeout,
                       0,
                       NULL,
                       0))
        return false;

    if (profile->config_order == GOODIX_ACTIVATION_CONFIG_AFTER_TLS &&
        !append_action(activation,
                       GOODIX_ACTIVATION_UPLOAD_CONFIG,
                       timeout,
                       0,
                       profile->runtime_configuration ? activation->configuration :
                           profile->configuration,
                       GOODIX_ACTIVATION_CONFIG_SIZE))
        return false;

    return true;
}

static const GoodixActivationProfile *
find_profile(const GoodixActivation *activation, const char *firmware)
{
    for (size_t i = 0; i < activation->profile_count; i++) {
        if (strcmp(activation->profiles[i].firmware, firmware) == 0)
            return &activation->profiles[i];
    }
    return NULL;
}

static void
begin_cleanup(GoodixActivation *activation, GoodixActivationOutcome outcome)
{
    activation->action_count = 0;
    activation->action_index = 0;
    activation->phase = PHASE_CLEANUP;
    activation->cleanup_outcome = outcome;
    append_action(activation,
                  GOODIX_ACTIVATION_STOP_IO,
                  0,
                  0,
                  NULL,
                  0);
    append_action(activation,
                  GOODIX_ACTIVATION_CLEAR_SECRETS,
                  0,
                  0,
                  NULL,
                  0);
}

GoodixActivationResult
goodix_activation_new(const GoodixActivationDiscovery *discovery,
                      const GoodixActivationProfile *profiles,
                      size_t profile_count,
                      GoodixActivation **activation)
{
    GoodixActivation *created;

    if (activation == NULL)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    *activation = NULL;
    if (discovery == NULL || discovery->command_timeout_ms == 0 ||
        discovery->nop_timeout_ms == 0 ||
        (profile_count > 0 && profiles == NULL))
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;

    for (size_t i = 0; i < profile_count; i++) {
        if (!valid_profile(discovery, &profiles[i]))
            return GOODIX_ACTIVATION_INVALID_PROFILE;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(profiles[i].firmware, profiles[j].firmware) == 0)
                return GOODIX_ACTIVATION_INVALID_PROFILE;
        }
    }

    created = calloc(1, sizeof(*created));
    if (created == NULL)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    created->discovery = *discovery;
    created->profiles = profiles;
    created->profile_count = profile_count;
    created->outcome = GOODIX_ACTIVATION_PENDING;
    created->cleanup_outcome = GOODIX_ACTIVATION_PENDING;
    if (!append_discovery(created)) {
        free(created);
        return GOODIX_ACTIVATION_INVALID_PROFILE;
    }

    *activation = created;
    return GOODIX_ACTIVATION_OK;
}

void
goodix_activation_free(GoodixActivation *activation)
{
    if (activation != NULL) {
        volatile uint8_t *bytes = (volatile uint8_t *)activation;
        for (size_t i = 0; i < sizeof(*activation); i++)
            bytes[i] = 0;
    }
    free(activation);
}

bool
goodix_activation_current(const GoodixActivation *activation,
                          GoodixActivationAction *action)
{
    if (activation == NULL || action == NULL ||
        activation->phase == PHASE_FINISHED ||
        activation->action_index >= activation->action_count)
        return false;
    *action = activation->actions[activation->action_index];
    return true;
}

GoodixActivationResult
goodix_activation_advance(GoodixActivation *activation,
                          GoodixActivationEvent event,
                          const char *firmware)
{
    GoodixActivationActionKind current;
    GoodixActivationOutcome failure;

    if (activation == NULL || activation->phase == PHASE_FINISHED ||
        activation->action_index >= activation->action_count)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    if (event < GOODIX_ACTIVATION_EVENT_SUCCEEDED ||
        event > GOODIX_ACTIVATION_EVENT_CANCELLED)
        return GOODIX_ACTIVATION_INVALID_EVENT;

    if (activation->phase == PHASE_CLEANUP) {
        if (activation->actions[activation->action_index].kind ==
            GOODIX_ACTIVATION_CLEAR_SECRETS) {
            volatile uint8_t *bytes = activation->configuration;
            for (size_t i = 0; i < sizeof(activation->configuration); i++)
                bytes[i] = 0;
            activation->configuration_ready = false;
        }
        activation->action_index++;
        if (activation->action_index == activation->action_count) {
            activation->phase = PHASE_FINISHED;
            activation->outcome = activation->cleanup_outcome;
        }
        return GOODIX_ACTIVATION_OK;
    }

    if (event != GOODIX_ACTIVATION_EVENT_SUCCEEDED) {
        switch (event) {
        case GOODIX_ACTIVATION_EVENT_TIMED_OUT:
            failure = GOODIX_ACTIVATION_TIMED_OUT;
            break;
        case GOODIX_ACTIVATION_EVENT_IO_FAILED:
            failure = GOODIX_ACTIVATION_IO_FAILED;
            break;
        case GOODIX_ACTIVATION_EVENT_CANCELLED:
            failure = GOODIX_ACTIVATION_CANCELLED;
            break;
        case GOODIX_ACTIVATION_EVENT_SUCCEEDED:
            return GOODIX_ACTIVATION_INVALID_EVENT;
        }
        begin_cleanup(activation, failure);
        return GOODIX_ACTIVATION_OK;
    }

    current = activation->actions[activation->action_index].kind;
    if (current == GOODIX_ACTIVATION_BUILD_CONFIG &&
        !activation->configuration_ready)
        return GOODIX_ACTIVATION_INVALID_EVENT;
    if (current == GOODIX_ACTIVATION_READ_PSK_STATUS &&
        !activation->psk_decision_ready)
        return GOODIX_ACTIVATION_INVALID_EVENT;
    if (current == GOODIX_ACTIVATION_QUERY_FIRMWARE) {
        if (firmware == NULL)
            return GOODIX_ACTIVATION_INVALID_EVENT;
        activation->profile = find_profile(activation, firmware);
        if (activation->profile == NULL) {
            begin_cleanup(activation,
                          GOODIX_ACTIVATION_UNSUPPORTED_FIRMWARE);
            return GOODIX_ACTIVATION_OK;
        }
        if (!append_profile_actions(activation, activation->profile))
            return GOODIX_ACTIVATION_INVALID_PROFILE;
    } else if (firmware != NULL) {
        return GOODIX_ACTIVATION_INVALID_EVENT;
    }

    if (current == GOODIX_ACTIVATION_READ_PSK_STATUS &&
        !activation->psk_write_needed &&
        activation->action_index + 1 < activation->action_count &&
        activation->actions[activation->action_index + 1].kind ==
            GOODIX_ACTIVATION_WRITE_PSK)
        activation->action_index++;

    activation->action_index++;
    if (activation->action_index == activation->action_count) {
        if (activation->deactivating)
            begin_cleanup(activation, activation->idle_outcome);
        else {
            activation->phase = PHASE_FINISHED;
            activation->outcome = GOODIX_ACTIVATION_ACTIVATED;
        }
    }
    return GOODIX_ACTIVATION_OK;
}

GoodixActivationOutcome
goodix_activation_outcome(const GoodixActivation *activation)
{
    if (activation == NULL)
        return GOODIX_ACTIVATION_IO_FAILED;
    return activation->outcome;
}

bool
goodix_activation_action_command(GoodixActivationActionKind action,
                                 uint8_t *command)
{
    uint8_t value;

    switch (action) {
    case GOODIX_ACTIVATION_NOP:
        value = 0x00;
        break;
    case GOODIX_ACTIVATION_ENABLE_CHIP:
        value = 0x96;
        break;
    case GOODIX_ACTIVATION_QUERY_FIRMWARE:
        value = 0xa8;
        break;
    case GOODIX_ACTIVATION_READ_PSK_STATUS:
        value = 0xe4;
        break;
    case GOODIX_ACTIVATION_WRITE_PSK:
        value = 0xe0;
        break;
    case GOODIX_ACTIVATION_QUERY_IAP:
        value = 0xf6;
        break;
    case GOODIX_ACTIVATION_RESET_SENSOR:
        value = 0xa2;
        break;
    case GOODIX_ACTIVATION_READ_SENSOR_ID:
        value = 0x82;
        break;
    case GOODIX_ACTIVATION_READ_OTP:
        value = 0xa6;
        break;
    case GOODIX_ACTIVATION_MCU_IDLE:
        value = 0x70;
        break;
    case GOODIX_ACTIVATION_UPLOAD_CONFIG:
        value = 0x90;
        break;
    case GOODIX_ACTIVATION_REQUEST_TLS:
        value = 0xd0;
        break;
    case GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED:
        value = 0xd4;
        break;
    case GOODIX_ACTIVATION_BUILD_CONFIG:
    case GOODIX_ACTIVATION_START_RECEIVE:
    case GOODIX_ACTIVATION_EXCHANGE_TLS:
    case GOODIX_ACTIVATION_WAIT_TLS_QUIET:
    case GOODIX_ACTIVATION_STOP_IO:
    case GOODIX_ACTIVATION_CLEAR_SECRETS:
        return false;
    default:
        return false;
    }

    if (command != NULL)
        *command = value;
    return command != NULL;
}

GoodixActivationResult
goodix_activation_set_configuration(GoodixActivation *activation,
                                     const uint8_t *configuration, size_t length)
{
    GoodixActivationAction action;
    if (!goodix_activation_current(activation, &action) ||
        action.kind != GOODIX_ACTIVATION_BUILD_CONFIG || configuration == NULL ||
        length != GOODIX_ACTIVATION_CONFIG_SIZE)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    memcpy(activation->configuration, configuration, length);
    activation->configuration_ready = true;
    return GOODIX_ACTIVATION_OK;
}

GoodixActivationResult
goodix_activation_set_community_psk_write(GoodixActivation *activation,
                                          bool needed)
{
    GoodixActivationAction action;

    if (!goodix_activation_current(activation, &action) ||
        action.kind != GOODIX_ACTIVATION_READ_PSK_STATUS)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    activation->psk_decision_ready = true;
    activation->psk_write_needed = needed;
    return GOODIX_ACTIVATION_OK;
}

GoodixActivationResult
goodix_activation_deactivate(GoodixActivation *activation)
{
    if (activation == NULL || activation->phase != PHASE_FINISHED ||
        activation->outcome != GOODIX_ACTIVATION_ACTIVATED)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    activation->phase = PHASE_RUNNING;
    activation->outcome = GOODIX_ACTIVATION_PENDING;
    activation->deactivating = true;
    activation->idle_outcome = GOODIX_ACTIVATION_DEACTIVATED;
    activation->action_count = 0;
    activation->action_index = 0;
    append_action(activation, GOODIX_ACTIVATION_MCU_IDLE,
                  activation->profile->command_timeout_ms, 0, NULL, 0);
    return GOODIX_ACTIVATION_OK;
}

GoodixActivationProfile
goodix_activation_profile_55b4(void)
{
    return (GoodixActivationProfile){
        .firmware = "GF3208_RTSEC_APP_10042",
        .runtime_configuration = true,
        .post_reset_nop = true,
        .read_otp = true,
        .config_order = GOODIX_ACTIVATION_CONFIG_AFTER_TLS,
        .notify_tls_established = true,
        .command_timeout_ms = 5000,
        .tls_timeout_ms = 5000,
        .tls_quiet_ms = 15,
    };
}

GoodixActivationResult
goodix_activation_cancel_after_tls(GoodixActivation *activation)
{
    GoodixActivationAction action;
    if (!goodix_activation_current(activation, &action) ||
        action.kind != GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED)
        return GOODIX_ACTIVATION_INVALID_ARGUMENT;
    activation->deactivating = true;
    activation->idle_outcome = GOODIX_ACTIVATION_CANCELLED;
    activation->action_count = 0;
    activation->action_index = 0;
    append_action(activation, GOODIX_ACTIVATION_MCU_IDLE,
                  activation->profile->command_timeout_ms, 0, NULL, 0);
    return GOODIX_ACTIVATION_OK;
}
