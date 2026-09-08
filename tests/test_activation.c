/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_activation.h"
#include <assert.h>
#include <string.h>

static void
advance_ok(GoodixActivation *activation, const char *firmware)
{
    assert(goodix_activation_advance(activation,
                                     GOODIX_ACTIVATION_EVENT_SUCCEEDED,
                                     firmware) == GOODIX_ACTIVATION_OK);
}

int main(void)
{
    GoodixActivationDiscovery discovery = {
        .command_timeout_ms = 5000,
        .nop_timeout_ms = 100,
    };
    GoodixActivationProfile profile = goodix_activation_profile_55b4();
    GoodixActivation *activation = NULL;
    GoodixActivationAction action;

    assert(goodix_activation_new(&discovery, &profile, 1, &activation) ==
           GOODIX_ACTIVATION_OK);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_START_RECEIVE);
    advance_ok(activation, NULL);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_NOP);
    advance_ok(activation, NULL);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_QUERY_FIRMWARE);
    advance_ok(activation, profile.firmware);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_READ_PSK_STATUS);
    assert(goodix_activation_advance(activation,
                                     GOODIX_ACTIVATION_EVENT_SUCCEEDED,
                                     NULL) == GOODIX_ACTIVATION_INVALID_EVENT);
    assert(goodix_activation_set_community_psk_write(activation, false) ==
           GOODIX_ACTIVATION_OK);
    advance_ok(activation, NULL);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_RESET_SENSOR);
    goodix_activation_free(activation);

    assert(goodix_activation_new(&discovery, &profile, 1, &activation) ==
           GOODIX_ACTIVATION_OK);
    advance_ok(activation, NULL);
    advance_ok(activation, NULL);
    advance_ok(activation, profile.firmware);
    assert(goodix_activation_set_community_psk_write(activation, true) ==
           GOODIX_ACTIVATION_OK);
    advance_ok(activation, NULL);
    assert(goodix_activation_current(activation, &action));
    assert(action.kind == GOODIX_ACTIVATION_WRITE_PSK);
    goodix_activation_free(activation);
}
