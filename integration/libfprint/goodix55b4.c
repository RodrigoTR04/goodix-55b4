/*
 * Goodix 27c6:55b4 image device transport
 *
 * Copyright (C) 2026 the libfprint-goodix-55b4 authors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#define FP_COMPONENT "goodix55b4"

#include "drivers_api.h"
#include "fp-image-device-private.h"
#include "goodix_finger.h"
#include "goodix_image.h"
#include "goodix_key.h"
#include "goodix_psk.h"
#include "goodix_seal.h"
#include "goodix_session.h"
#include "goodix_sigfm.h"
#include "goodix_security.h"
#include <openssl/crypto.h>

#define GOODIX55B4_INTERFACE 0
#define GOODIX55B4_EP_OUT (1 | FPI_USB_ENDPOINT_OUT)
#define GOODIX55B4_EP_IN (2 | FPI_USB_ENDPOINT_IN)
#define GOODIX55B4_IN_BLOCK_SIZE 65536
#define GOODIX55B4_IO_TIMEOUT_MS 5000
#define GOODIX55B4_IMAGE_SCALE 3
#define GOODIX55B4_ENROLL_STAGES 5

struct _FpiDeviceGoodix55b4
{
  FpImageDevice parent;

  GoodixSession    *session;
  GoodixImageDecoder *image_decoder;
  GoodixFingerCycle *finger_cycle;
  guint64            generation;
  GCancellable     *io_cancel;
  GSource          *timer;
  guint             pending_transfers;
  gboolean          in_pending;
  gboolean          activating;
  gboolean          activation_error_reported;
  gboolean          deactivating;
  gboolean          stopping;
  gboolean          claimed;
  gboolean          opened;
  gboolean          closing;
  gboolean          finish_action_on_idle;
  gboolean          cycle_start_pending;
  guint             enroll_captured;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix55b4,
                      fpi_device_goodix55b4,
                      FPI,
                      DEVICE_GOODIX55B4,
                      FpImageDevice);
G_DEFINE_TYPE (FpiDeviceGoodix55b4,
               fpi_device_goodix55b4,
               FP_TYPE_IMAGE_DEVICE);

static void goodix55b4_queue_read (FpiDeviceGoodix55b4 *self);
static void goodix55b4_schedule (FpiDeviceGoodix55b4 *self);
static void goodix55b4_submit_block (void *data, const uint8_t *block, size_t length);
static void goodix55b4_capture_reply (void *user_data, uint8_t command,
                                      bool success, const uint8_t *reply,
                                      size_t reply_length);
static void goodix55b4_capture_frame (void *user_data, bool success,
                                      const uint8_t *plaintext,
                                      size_t plaintext_length);
static void goodix55b4_cycle_failure (FpiDeviceGoodix55b4 *self,
                                      GoodixFingerResult result);
static void goodix55b4_maybe_finish_action (FpiDeviceGoodix55b4 *self);
static void goodix55b4_maybe_start_cycle (FpiDeviceGoodix55b4 *self);

static void
goodix55b4_note_disconnect (FpiDeviceGoodix55b4 *self,
                            const GError        *error)
{
  gboolean removed = FALSE;

  if (!g_error_matches (error, G_USB_DEVICE_ERROR,
                        G_USB_DEVICE_ERROR_NO_DEVICE))
    return;

  if (self->finger_cycle != NULL)
    goodix_finger_cycle_disconnect (self->finger_cycle);

  /* FpContext normally observes USB removal first. A pending bulk transfer
   * can win that race, so mark the device removed before completing the
   * action; libfprint will then translate its result to DEVICE_ERROR_REMOVED. */
  g_object_get (self, "removed", &removed, NULL);
  if (!removed)
    fpi_device_remove (FP_DEVICE (self));
}

static void
goodix55b4_finish_deactivation_when_idle (FpiDeviceGoodix55b4 *self)
{
  GoodixFingerState state;

  state = self->finger_cycle != NULL ?
    goodix_finger_cycle_state (self->finger_cycle) : GOODIX_FINGER_STATE_IDLE;
  if (!self->deactivating || self->session == NULL ||
      goodix_session_capture_busy (self->session) ||
      (state != GOODIX_FINGER_STATE_IDLE &&
       state != GOODIX_FINGER_STATE_COMPLETE))
    return;
  goodix_session_deactivate (self->session);
  goodix55b4_schedule (self);
}

static gboolean
goodix55b4_validate_usb (FpiDeviceGoodix55b4 *self,
                         GError              **error)
{
  g_autoptr(GPtrArray) interfaces = NULL;
  gboolean found_in = FALSE;
  gboolean found_out = FALSE;

  interfaces = g_usb_device_get_interfaces (
    fpi_device_get_usb_device (FP_DEVICE (self)), error);
  if (interfaces == NULL)
    return FALSE;

  for (guint i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *interface = g_ptr_array_index (interfaces, i);
      g_autoptr(GPtrArray) endpoints = NULL;

      if (g_usb_interface_get_number (interface) != GOODIX55B4_INTERFACE ||
          g_usb_interface_get_alternate (interface) != 0)
        continue;

      endpoints = g_usb_interface_get_endpoints (interface);
      if (endpoints == NULL)
        continue;
      for (guint j = 0; j < endpoints->len; j++)
        {
          GUsbEndpoint *endpoint = g_ptr_array_index (endpoints, j);
          guint8 address = g_usb_endpoint_get_address (endpoint);

          if (address == GOODIX55B4_EP_IN &&
              g_usb_endpoint_get_direction (endpoint) ==
                G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST)
            found_in = TRUE;
          else if (address == GOODIX55B4_EP_OUT &&
                   g_usb_endpoint_get_direction (endpoint) ==
                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE)
            found_out = TRUE;
        }
    }

  if (!found_in || !found_out)
    {
      *error = fpi_device_error_new_msg (
        FP_DEVICE_ERROR_NOT_SUPPORTED,
        "Goodix 55b4 bulk endpoints are missing");
      return FALSE;
    }

  return TRUE;
}

static guint64
goodix55b4_now_ms (void)
{
  return (guint64) (g_get_monotonic_time () / 1000);
}

static void
goodix55b4_clear_cycle (FpiDeviceGoodix55b4 *self)
{
  self->cycle_start_pending = FALSE;
  g_clear_pointer (&self->finger_cycle, goodix_finger_cycle_free);
  g_clear_pointer (&self->image_decoder, goodix_image_decoder_free);
}

static void
goodix55b4_maybe_start_cycle (FpiDeviceGoodix55b4 *self)
{
  GoodixFingerState state;
  GoodixFingerResult result;

  if (!self->cycle_start_pending || self->session == NULL ||
      self->closing || self->stopping || self->deactivating ||
      self->finish_action_on_idle || self->finger_cycle == NULL)
    return;
  state = goodix_finger_cycle_state (self->finger_cycle);
  if (state != GOODIX_FINGER_STATE_IDLE &&
      state != GOODIX_FINGER_STATE_COMPLETE)
    return;
  if (state == GOODIX_FINGER_STATE_COMPLETE)
    {
      result = goodix_finger_cycle_reset (self->finger_cycle);
      if (result != GOODIX_FINGER_OK)
        {
          self->cycle_start_pending = FALSE;
          goodix55b4_cycle_failure (self, result);
          return;
        }
    }
  self->cycle_start_pending = FALSE;
  result = goodix_finger_cycle_start (self->finger_cycle,
                                      goodix55b4_now_ms ());
  if (result != GOODIX_FINGER_OK)
    goodix55b4_cycle_failure (self, result);
}

static GError *
goodix55b4_finger_error (GoodixFingerResult result)
{
  switch (result)
    {
    case GOODIX_FINGER_CANCELLED:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                  "Goodix capture cancelled");
    case GOODIX_FINGER_TIMEOUT:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                  "Goodix capture timed out");
    case GOODIX_FINGER_DISCONNECTED:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                                  "Goodix reader disconnected");
    case GOODIX_FINGER_OK:
    case GOODIX_FINGER_INVALID_ARGUMENT:
    case GOODIX_FINGER_INVALID_LENGTH:
    case GOODIX_FINGER_INVALID_EVENT:
    case GOODIX_FINGER_THRESHOLD_OUT_OF_RANGE:
    case GOODIX_FINGER_THRESHOLDS_UNAVAILABLE:
    case GOODIX_FINGER_BUFFER_TOO_SMALL:
    case GOODIX_FINGER_NO_MEMORY:
    case GOODIX_FINGER_BUSY:
    case GOODIX_FINGER_STALE_ACTION:
    case GOODIX_FINGER_IO_ERROR:
    case GOODIX_FINGER_IMAGE_ERROR:
    case GOODIX_FINGER_EMIT_FAILED:
    default:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                       "%s", goodix_finger_result_string (result));
    }
}

static gboolean
goodix55b4_unseal_features (const guint8 *sealed, size_t sealed_length,
                            GoodixSigfmFeatures **features)
{
  guint8 wrap[GOODIX_WRAP_KEY_SIZE];
  guint8 plain[GOODIX_SEAL_MAX_PLAIN_BYTES];
  size_t plain_length = 0;
  GoodixSealResult seal_result;
  GoodixSigfmResult sigfm_result;

  *features = NULL;
  if (!goodix_key_load_or_create_wrap (wrap))
    return FALSE;
  seal_result = goodix_seal_unwrap (wrap, sealed, sealed_length, plain,
                                    sizeof (plain), &plain_length);
  OPENSSL_cleanse (wrap, sizeof (wrap));
  if (seal_result != GOODIX_SEAL_OK)
    {
      OPENSSL_cleanse (plain, sizeof (plain));
      return FALSE;
    }
  sigfm_result = goodix_sigfm_deserialize (plain, plain_length, features);
  OPENSSL_cleanse (plain, sizeof (plain));
  return sigfm_result == GOODIX_SIGFM_OK && *features != NULL;
}

static gboolean
goodix55b4_store_features (FpPrint                   *print,
                           const GoodixSigfmFeatures *features)
{
  g_autoptr(GVariant) existing = NULL;
  g_autoptr(GVariant) packed = NULL;
  GVariantBuilder builder;
  guint existing_count = 0;
  guint8 *blob = NULL;
  size_t blob_length = 0;
  guint8 wrap[GOODIX_WRAP_KEY_SIZE];
  guint8 sealed[GOODIX_SEAL_MAX_BYTES];
  size_t sealed_length = 0;
  GoodixSigfmResult result;

  if (print == NULL || features == NULL)
    return FALSE;
  result = goodix_sigfm_serialize (features, &blob, &blob_length);
  if (result != GOODIX_SIGFM_OK)
    return FALSE;
  if (!goodix_key_load_or_create_wrap (wrap))
    {
      goodix_sigfm_free_buffer (blob, blob_length);
      return FALSE;
    }
  if (goodix_seal_wrap (wrap, blob, blob_length, sealed, sizeof (sealed),
                        &sealed_length) != GOODIX_SEAL_OK)
    {
      OPENSSL_cleanse (wrap, sizeof (wrap));
      OPENSSL_cleanse (sealed, sizeof (sealed));
      goodix_sigfm_free_buffer (blob, blob_length);
      return FALSE;
    }
  OPENSSL_cleanse (wrap, sizeof (wrap));
  goodix_sigfm_free_buffer (blob, blob_length);
  g_object_get (print, "fpi-data", &existing, NULL);
  if (existing != NULL &&
      !g_variant_is_of_type (existing, G_VARIANT_TYPE ("aay")))
    {
      OPENSSL_cleanse (sealed, sizeof (sealed));
      return FALSE;
    }
  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));
  if (existing != NULL)
    {
      GVariantIter iter;
      GVariant *item;

      g_variant_iter_init (&iter, existing);
      while ((item = g_variant_iter_next_value (&iter)) != NULL)
        {
          gsize item_length = 0;
          const guint8 *item_bytes;
          GoodixSigfmFeatures *stored = NULL;

          item_bytes = g_variant_get_fixed_array (item, &item_length, 1);
          if (item_bytes == NULL || item_length == 0 ||
              item_length > GOODIX_SEAL_MAX_BYTES ||
              existing_count >= GOODIX_SIGFM_MAX_TEMPLATES ||
              !goodix55b4_unseal_features (item_bytes, item_length, &stored))
            {
              goodix_sigfm_features_free (stored);
              g_variant_unref (item);
              g_variant_builder_clear (&builder);
              OPENSSL_cleanse (sealed, sizeof (sealed));
              return FALSE;
            }
          goodix_sigfm_features_free (stored);
          g_variant_builder_add_value (&builder, item);
          existing_count++;
        }
    }
  if (existing_count >= GOODIX_SIGFM_MAX_TEMPLATES)
    {
      g_variant_builder_clear (&builder);
      OPENSSL_cleanse (sealed, sizeof (sealed));
      return FALSE;
    }

  g_variant_builder_add_value (&builder,
                               g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                          sealed, sealed_length, 1));
  packed = g_variant_builder_end (&builder);
  g_object_set (print, "fpi-data",
                g_steal_pointer (&packed),
                NULL);
  OPENSSL_cleanse (sealed, sizeof (sealed));
  return TRUE;
}

static gboolean
goodix55b4_score_print (FpPrint                     *print,
                        const GoodixSigfmFeatures   *probe,
                        int32_t                     *score)
{
  g_autoptr(GVariant) data = NULL;
  GVariantIter iter;
  GVariant *item;
  gboolean found = FALSE;
  guint template_count = 0;
  int32_t best = 0;

  if (print == NULL || fpi_print_get_type (print) != FPI_PRINT_RAW)
    return FALSE;
  g_object_get (print, "fpi-data", &data, NULL);
  if (data == NULL || !g_variant_is_of_type (data, G_VARIANT_TYPE ("aay")) ||
      probe == NULL || score == NULL)
    return FALSE;
  g_variant_iter_init (&iter, data);
  while ((item = g_variant_iter_next_value (&iter)) != NULL)
    {
      gsize blob_length = 0;
      const guint8 *blob = g_variant_get_fixed_array (item, &blob_length, 1);
      GoodixSigfmFeatures *enrolled = NULL;
      int32_t candidate_score = 0;
      GoodixSigfmResult result;

      if (template_count >= GOODIX_SIGFM_MAX_TEMPLATES ||
          blob == NULL || blob_length == 0 ||
          blob_length > GOODIX_SEAL_MAX_BYTES ||
          !goodix55b4_unseal_features (blob, blob_length, &enrolled))
        {
          g_variant_unref (item);
          goodix_sigfm_features_free (enrolled);
          return FALSE;
        }
      template_count++;
      g_variant_unref (item);
      result = goodix_sigfm_score (probe, enrolled, &candidate_score);
      fp_dbg ("sanitized SIGFM template keypoints=%zu score=%d",
              goodix_sigfm_keypoint_count (enrolled), candidate_score);
      goodix_sigfm_features_free (enrolled);
      if (result != GOODIX_SIGFM_OK)
        return FALSE;
      if (!found || candidate_score > best)
        {
          best = candidate_score;
          found = TRUE;
        }
    }
  if (!found)
    return FALSE;
  *score = best;
  return TRUE;
}

static void
goodix55b4_maybe_finish_action (FpiDeviceGoodix55b4 *self)
{
  GoodixFingerState state;

  if (!self->finish_action_on_idle)
    return;
  state = self->finger_cycle != NULL ?
    goodix_finger_cycle_state (self->finger_cycle) : GOODIX_FINGER_STATE_IDLE;
  if (self->session != NULL && goodix_session_capture_busy (self->session))
    return;
  if (state != GOODIX_FINGER_STATE_IDLE &&
      state != GOODIX_FINGER_STATE_COMPLETE)
    return;
  self->finish_action_on_idle = FALSE;
  /* CAPTURE -> DEACTIVATING is the cancellation transition; the enroll or
   * identify action still completes after the release tail reaches idle. */
  fpi_image_device_deactivate (FP_IMAGE_DEVICE (self), TRUE);
}

static bool
goodix55b4_cycle_emit (void *user_data, GoodixFingerAction action,
                       uint8_t command, const uint8_t *payload,
                       size_t payload_length)
{
  FpiDeviceGoodix55b4 *self = user_data;
  gboolean expects_reply;

  if (self->session == NULL || self->closing || self->stopping)
    return false;
  fp_dbg ("capture emit action=%d command=0x%02x reply=%s",
          action, command,
          (action == GOODIX_FINGER_ACTION_PROBE ||
           action == GOODIX_FINGER_ACTION_FDT_DOWN ||
           action == GOODIX_FINGER_ACTION_FDT_UP) ? "yes" : "no");
  expects_reply = action == GOODIX_FINGER_ACTION_PROBE ||
    action == GOODIX_FINGER_ACTION_FDT_DOWN ||
    action == GOODIX_FINGER_ACTION_FDT_UP;
  return goodix_session_capture_command (self->session, command, payload,
                                         payload_length, expects_reply,
                                         goodix55b4_now_ms ());
}

static bool
goodix55b4_image_sink (void *user_data, const uint8_t *pixels,
                       size_t pixel_count)
{
  FpiDeviceGoodix55b4 *self = user_data;
  FpDevice *device = FP_DEVICE (self);
  FpiDeviceAction action;
  GoodixFingerStability stability;
  guint8 native[GOODIX_IMAGE_PIXELS];

  if (pixels == NULL || pixel_count != GOODIX_IMAGE_PIXELS)
    return false;
  if (goodix_finger_cycle_get_stability (self->finger_cycle, &stability))
    fp_dbg ("capture stability frames=%u pairs=%u mean-delta=%u.%03u max-delta=%u selected=%u gradient=%u.%03u",
            (guint) stability.frames, (guint) stability.compared_pairs,
            stability.mean_absolute_delta_milli / 1000,
            stability.mean_absolute_delta_milli % 1000,
            (guint) stability.maximum_absolute_delta,
            (guint) stability.selected_frame,
            stability.selected_gradient_milli / 1000,
            stability.selected_gradient_milli % 1000);
  memcpy (native, pixels, GOODIX_IMAGE_PIXELS);
  action = fpi_device_get_current_action (device);
  if (action == FPI_DEVICE_ACTION_CAPTURE)
    {
      FpImage *image;
      FpImage *scaled;

      image = fp_image_new (GOODIX_FORMAT_WIDTH, GOODIX_FORMAT_HEIGHT);
      if (image == NULL)
        {
          OPENSSL_cleanse (native, sizeof (native));
          return false;
        }
      memcpy (image->data, native, sizeof (native));
      OPENSSL_cleanse (native, sizeof (native));
      image->flags = FPI_IMAGE_COLORS_INVERTED;
      scaled = fpi_image_resize (image, GOODIX55B4_IMAGE_SCALE,
                                 GOODIX55B4_IMAGE_SCALE);
      OPENSSL_cleanse (image->data, sizeof (native));
      g_object_unref (image);
      if (scaled == NULL)
        return false;
      fpi_image_device_image_captured (FP_IMAGE_DEVICE (self), scaled);
      return true;
    }
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      FpPrint *print;
      GoodixSigfmFeatures *features = NULL;
      GoodixSigfmResult result;

      fpi_device_get_enroll_data (device, &print);
      result = goodix_sigfm_extract (native, sizeof (native), &features);
      fp_dbg ("sanitized SIGFM extraction status=%s keypoints=%zu",
              goodix_sigfm_result_string (result),
              goodix_sigfm_keypoint_count (features));
      if (result == GOODIX_SIGFM_NO_FEATURES)
        {
          OPENSSL_cleanse (native, sizeof (native));
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self),
                                       FP_DEVICE_RETRY_GENERAL);
          return true;
        }
      if (result != GOODIX_SIGFM_OK || features == NULL ||
          !goodix55b4_store_features (print, features))
        {
          goodix_sigfm_features_free (features);
          OPENSSL_cleanse (native, sizeof (native));
          return false;
        }
      goodix_sigfm_features_free (features);
      OPENSSL_cleanse (native, sizeof (native));
      self->enroll_captured++;
      fpi_device_enroll_progress (device, (gint) self->enroll_captured, NULL,
                                  NULL);
      if (self->enroll_captured >=
          (guint) fp_device_get_nr_enroll_stages (device))
        self->finish_action_on_idle = TRUE;
      else
        fpi_image_device_report_await_finger_off (FP_IMAGE_DEVICE (self));
      return true;
    }
  if (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY)
    {
      GPtrArray *templates = NULL;
      FpPrint *matched = NULL;
      gint i;
      int32_t best_score = -1;
      GoodixSigfmFeatures *probe = NULL;
      GoodixSigfmResult extract_result;

      extract_result = goodix_sigfm_extract (native, sizeof (native), &probe);
      fp_dbg ("sanitized SIGFM probe status=%s keypoints=%zu",
              goodix_sigfm_result_string (extract_result),
              goodix_sigfm_keypoint_count (probe));
      if (extract_result == GOODIX_SIGFM_NO_FEATURES)
        {
          goodix_sigfm_features_free (probe);
          OPENSSL_cleanse (native, sizeof (native));
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self),
                                       FP_DEVICE_RETRY_GENERAL);
          return true;
        }
      if (extract_result != GOODIX_SIGFM_OK || probe == NULL)
        {
          goodix_sigfm_features_free (probe);
          OPENSSL_cleanse (native, sizeof (native));
          return false;
        }
      if (action == FPI_DEVICE_ACTION_VERIFY)
        {
          FpPrint *candidate = NULL;
          int32_t score = 0;
          gboolean accepted;

          fpi_device_get_verify_data (device, &candidate);
          accepted = goodix55b4_score_print (candidate, probe, &score) &&
                              goodix_sigfm_accepts (score);
          goodix_sigfm_features_free (probe);
          OPENSSL_cleanse (native, sizeof (native));
          fpi_device_verify_report (device,
                                    accepted ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                    NULL, NULL);
          self->finish_action_on_idle = TRUE;
          return true;
        }
      fpi_device_get_identify_data (device, &templates);
      for (i = 0; templates != NULL && i < (gint) templates->len; i++)
        {
          FpPrint *candidate = g_ptr_array_index (templates, i);
          int32_t score = 0;

          if (!goodix55b4_score_print (candidate, probe, &score))
            continue;
          fp_dbg ("sanitized SIGFM score=%d", score);
          if (goodix_sigfm_accepts (score) && score > best_score)
            {
              matched = candidate;
              best_score = score;
            }
        }
      goodix_sigfm_features_free (probe);
      OPENSSL_cleanse (native, sizeof (native));
      fpi_device_identify_report (device, matched, NULL, NULL);
      self->finish_action_on_idle = TRUE;
      return true;
    }
  OPENSSL_cleanse (native, sizeof (native));
  return false;
}

static gboolean
goodix55b4_prepare_cycle (FpiDeviceGoodix55b4 *self, GError **error)
{
  GoodixFingerCycleConfig config = goodix_finger_cycle_config_default ();
  GoodixFingerResult result;

  goodix55b4_clear_cycle (self);
  self->generation++;
  if (self->generation == 0)
    self->generation = 1;
  if (goodix_image_decoder_new (GOODIX_IMAGE_FORMAT_55B4_108X88_12,
                                self->generation, &self->image_decoder) !=
      GOODIX_IMAGE_OK)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                         "Could not create Goodix image decoder");
      return FALSE;
    }
  /* These deadlines bound a hardware operation while allowing the reader's
   * observed cold-start latency. The sensor-specific margin remains zero
   * until a physical threshold qualification chooses otherwise. */
  config.probe_timeout_ms = 5000;
  config.background_timeout_ms = 15000;
  config.finger_down_timeout_ms = 120000;
  config.capture_timeout_ms = 10000;
  config.finger_up_timeout_ms = 120000;
  config.refresh_timeout_ms = 15000;
  config.sleep_timeout_ms = 5000;
  config.capture_frames = 1;
  result = goodix_finger_cycle_new (self->image_decoder, &config,
                                    goodix55b4_cycle_emit,
                                    goodix55b4_image_sink, self,
                                    &self->finger_cycle);
  if (result != GOODIX_FINGER_OK ||
      !goodix_session_capture_configure (self->session,
                                         goodix55b4_capture_reply,
                                         goodix55b4_capture_frame, self))
    {
      goodix55b4_clear_cycle (self);
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                         "Could not initialize Goodix capture cycle");
      return FALSE;
    }
  return TRUE;
}

static void
goodix55b4_cycle_failure (FpiDeviceGoodix55b4 *self,
                          GoodixFingerResult result)
{
  if (result == GOODIX_FINGER_OK || result == GOODIX_FINGER_CANCELLED)
    return;
  if (!self->closing && !self->deactivating)
    fpi_image_device_session_error (FP_IMAGE_DEVICE (self),
                                    goodix55b4_finger_error (result));
}

static void
goodix55b4_capture_reply (void *user_data, uint8_t command, bool success,
                           const uint8_t *reply, size_t reply_length)
{
  FpiDeviceGoodix55b4 *self = user_data;
  GoodixFingerAction action;
  GoodixFingerResult result;

  if (self->finger_cycle == NULL)
    return;
  fp_dbg ("capture reply command=0x%02x success=%s length=%zu",
          command, success ? "yes" : "no", reply_length);
  switch (command)
    {
    case GOODIX_FINGER_COMMAND_FDT_MODE:
      action = GOODIX_FINGER_ACTION_PROBE;
      break;
    case GOODIX_FINGER_COMMAND_FDT_DOWN:
      action = GOODIX_FINGER_ACTION_FDT_DOWN;
      break;
    case GOODIX_FINGER_COMMAND_FDT_UP:
      action = GOODIX_FINGER_ACTION_FDT_UP;
      break;
    case GOODIX_FINGER_COMMAND_GET_IMAGE:
      action = goodix_finger_cycle_action (self->finger_cycle);
      break;
    case GOODIX_FINGER_COMMAND_SLEEP:
      action = GOODIX_FINGER_ACTION_SLEEP;
      break;
    default:
      return;
    }
  result = goodix_finger_cycle_command_complete (
    self->finger_cycle, goodix55b4_now_ms (), action, success, reply,
    reply_length);
  /* Report only validated FDT transitions.  In particular, a transport ACK
   * is not enough to claim that a finger is present.  Reporting removal at
   * FDT_UP also matches the other Goodix drivers; our deactivation path keeps
   * the bounded background-refresh and sleep tail running after this report. */
  if (success && result == GOODIX_FINGER_OK &&
      action == GOODIX_FINGER_ACTION_FDT_DOWN)
    fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), TRUE);
  else if (success && result == GOODIX_FINGER_OK &&
           action == GOODIX_FINGER_ACTION_FDT_UP)
    fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), FALSE);
  else if (!success || result != GOODIX_FINGER_OK)
    goodix55b4_cycle_failure (self, result);
  goodix55b4_finish_deactivation_when_idle (self);
  goodix55b4_maybe_finish_action (self);
  goodix55b4_maybe_start_cycle (self);
}

static void
goodix55b4_capture_frame (void *user_data, bool success,
                           const uint8_t *plaintext, size_t plaintext_length)
{
  FpiDeviceGoodix55b4 *self = user_data;
  GoodixFingerAction action;
  GoodixFingerResult result;
  gboolean absent;

  if (self->finger_cycle == NULL)
    return;
  action = goodix_finger_cycle_action (self->finger_cycle);
  fp_dbg ("capture frame action=%d success=%s length=%zu",
          action, success ? "yes" : "no", plaintext_length);
  if (!success)
    {
      result = goodix_finger_cycle_frame_failed (self->finger_cycle,
                                                 goodix55b4_now_ms ());
      goodix55b4_cycle_failure (self, result);
      goodix55b4_maybe_finish_action (self);
      return;
    }
  absent = action == GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND ||
    action == GOODIX_FINGER_ACTION_REFRESH_BACKGROUND;
  {
    GoodixImageFrame frame = {
      .format = GOODIX_IMAGE_FORMAT_55B4_108X88_12,
      .generation = self->generation,
      .data = plaintext,
      .length = plaintext_length,
    };
    result = goodix_finger_cycle_frame_complete (self->finger_cycle,
                                                 goodix55b4_now_ms (), &frame,
                                                 absent);
  }
  if (result != GOODIX_FINGER_OK)
    goodix55b4_cycle_failure (self, result);
  goodix55b4_finish_deactivation_when_idle (self);
  goodix55b4_maybe_finish_action (self);
  goodix55b4_maybe_start_cycle (self);
}

static void
goodix55b4_finish_close (FpiDeviceGoodix55b4 *self)
{
  g_autoptr(GError) error = NULL;
  gboolean removed = FALSE;

  if (!self->closing || self->pending_transfers != 0)
    return;

  g_object_get (self, "removed", &removed, NULL);
  if (self->claimed && !removed)
    {
      g_usb_device_release_interface (
        fpi_device_get_usb_device (FP_DEVICE (self)),
        GOODIX55B4_INTERFACE,
        0,
        &error);
      self->claimed = FALSE;
    }
  else if (removed)
    self->claimed = FALSE;

  self->closing = FALSE;
  goodix55b4_clear_cycle (self);
  g_clear_pointer (&self->session, goodix_session_free);
  g_clear_object (&self->io_cancel);
  fpi_image_device_close_complete (FP_IMAGE_DEVICE (self),
                                   g_steal_pointer (&error));
}

static void
goodix55b4_out_cb (FpiUsbTransfer *transfer,
                   FpDevice       *device,
                   gpointer        user_data,
                   GError         *error)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);

  g_assert (self->pending_transfers > 0);
  self->pending_transfers--;

  OPENSSL_cleanse (transfer->buffer, transfer->length);
  if (self->session != NULL && !self->closing)
    {
      goodix55b4_note_disconnect (self, error);
      goodix_session_out_complete (self->session,
                                   error == NULL && transfer->actual_length == transfer->length);
    }
  goodix55b4_schedule (self);

  goodix55b4_finish_close (self);
}

static void
goodix55b4_submit_block (void          *user_data,
                         const uint8_t *block,
                         size_t         block_length)
{
  FpiDeviceGoodix55b4 *self = user_data;
  FpiUsbTransfer *transfer;
  guint8 *copy;

  if (!self->opened || self->closing || self->stopping)
    return;

  copy = g_memdup2 (block, block_length);
  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk_full (transfer,
                                   GOODIX55B4_EP_OUT,
                                   copy,
                                   block_length,
                                   g_free);
  self->pending_transfers++;
  fpi_usb_transfer_submit (transfer,
                           GOODIX55B4_IO_TIMEOUT_MS,
                           self->io_cancel,
                           goodix55b4_out_cb,
                           NULL);
}

static void
goodix55b4_in_cb (FpiUsbTransfer *transfer,
                  FpDevice       *device,
                  gpointer        user_data,
                  GError         *error)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);

  g_assert (self->pending_transfers > 0);
  self->pending_transfers--;

  self->in_pending = FALSE;
  if (self->session != NULL && !self->closing)
    {
      if (error == NULL)
        goodix_session_feed (self->session, transfer->buffer, transfer->actual_length);
      else if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          goodix55b4_note_disconnect (self, error);
          goodix_session_fail (self->session, FALSE);
        }
    }
  OPENSSL_cleanse (transfer->buffer, transfer->length);
  if (error == NULL)
    goodix55b4_queue_read (self);
  goodix55b4_schedule (self);

  goodix55b4_finish_close (self);
}

static void
goodix55b4_queue_read (FpiDeviceGoodix55b4 *self)
{
  FpiUsbTransfer *transfer;

  if (!self->opened || self->closing || self->stopping || self->in_pending ||
      (self->session != NULL &&
       goodix_session_state (self->session) == GOODIX_SESSION_STOPPING))
    return;

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer,
                              GOODIX55B4_EP_IN,
                              GOODIX55B4_IN_BLOCK_SIZE);
  self->in_pending = TRUE;
  self->pending_transfers++;
  fpi_usb_transfer_submit (transfer,
                           0,
                           self->io_cancel,
                           goodix55b4_in_cb,
                           NULL);
}

static void
goodix55b4_open (FpImageDevice *device)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);
  g_autoptr(GError) error = NULL;

  if (!goodix_security_disable_dumps ())
    {
      fpi_image_device_open_complete (device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Could not disable process dumps"));
      return;
    }
  if (fpi_log_is_debug_transfer_enabled ())
    {
      fpi_image_device_open_complete (device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Disable transfer dumps before opening Goodix"));
      return;
    }
  if (!goodix55b4_validate_usb (self, &error))
    {
      fpi_image_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  if (!g_usb_device_claim_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)),
        GOODIX55B4_INTERFACE,
        0,
        &error))
    {
      fpi_image_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  self->claimed = TRUE;
  self->opened = TRUE;
  self->io_cancel = g_cancellable_new ();
  goodix55b4_queue_read (self);
  fpi_image_device_open_complete (device, NULL);
}

static void
goodix55b4_close (FpImageDevice *device)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);

  self->opened = FALSE;
  self->closing = TRUE;
  if (self->timer != NULL)
    { g_source_destroy (self->timer); self->timer = NULL; }
  if (self->session != NULL)
    goodix_session_fail (self->session, TRUE);
  if (self->io_cancel != NULL)
    g_cancellable_cancel (self->io_cancel);
  goodix55b4_finish_close (self);
}

static GError *
goodix55b4_session_error (GoodixActivationOutcome outcome)
{
  switch (outcome)
    {
    case GOODIX_ACTIVATION_DEACTIVATED:
      return NULL;
    case GOODIX_ACTIVATION_CANCELLED:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Activation cancelled");
    case GOODIX_ACTIVATION_TIMED_OUT:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Activation timed out");
    case GOODIX_ACTIVATION_UNSUPPORTED_FIRMWARE:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "Unknown Goodix firmware");
    default:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Goodix session failed");
    }
}

static void
goodix55b4_pump (FpDevice *device, gpointer user_data)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);
  GoodixSessionState state;

  self->timer = NULL;
  if (self->session == NULL || self->closing)
    return;
  if (self->activating && fpi_device_action_is_cancelled (device))
    goodix_session_fail (self->session, TRUE);
  goodix_session_tick (self->session, g_get_monotonic_time () / 1000);
  state = goodix_session_state (self->session);
  if (state == GOODIX_SESSION_STOPPING)
    {
      self->stopping = TRUE;
      g_cancellable_cancel (self->io_cancel);
      if (self->pending_transfers == 0)
        {
          goodix_session_stopped (self->session);
          goodix_session_tick (self->session, g_get_monotonic_time () / 1000);
          state = goodix_session_state (self->session);
        }
    }
  if (state == GOODIX_SESSION_FINISHED)
    {
      GError *error = goodix55b4_session_error (goodix_session_outcome (self->session));
      gboolean activating = self->activating;
      gboolean activation_error_reported = self->activation_error_reported;
      gboolean deactivating = self->deactivating;
      self->activating = FALSE;
      self->activation_error_reported = FALSE;
      self->deactivating = FALSE;
      goodix55b4_clear_cycle (self);
      g_clear_pointer (&self->session, goodix_session_free);
      g_clear_object (&self->io_cancel);
      self->io_cancel = g_cancellable_new ();
      self->stopping = FALSE;
      if (activation_error_reported)
        g_clear_error (&error);
      else if (activating)
        fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), error);
      else if (deactivating)
        {
          g_clear_error (&error);
          fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
        }
      else
        fpi_image_device_session_error (FP_IMAGE_DEVICE (self), error);
      return;
    }
  if (state == GOODIX_SESSION_ACTIVE && self->activating)
    {
      g_autoptr(GError) error = NULL;
      if (!goodix55b4_prepare_cycle (self, &error))
        {
          self->activating = FALSE;
          self->activation_error_reported = TRUE;
          goodix_session_deactivate (self->session);
          fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self),
                                              g_steal_pointer (&error));
          goodix55b4_schedule (self);
          return;
        }
      self->activating = FALSE;
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
  goodix55b4_schedule (self);
}

static void
goodix55b4_schedule (FpiDeviceGoodix55b4 *self)
{
  if (self->session != NULL && !self->closing && self->timer == NULL &&
      goodix_session_state (self->session) != GOODIX_SESSION_ACTIVE)
    self->timer = fpi_device_add_timeout (FP_DEVICE (self), 1,
                                         goodix55b4_pump, NULL, NULL);
}

static void
goodix55b4_activate (FpImageDevice *device)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);
  guint8 key[GOODIX_TLS_PSK_SIZE];
  gboolean community = FALSE;

  if (goodix_key_load (key))
    {
      /* Optional host pairing file; do not overwrite the device PSK. */
    }
  else
    {
      goodix_psk_community_tls_key (key);
      community = TRUE;
    }
  self->session = goodix_session_new (key, sizeof (key), community,
                                      goodix55b4_submit_block, self);
  OPENSSL_cleanse (key, sizeof (key));
  if (self->session == NULL)
    {
      fpi_image_device_activate_complete (device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Could not create Goodix session"));
      return;
    }
  self->activating = TRUE;
  goodix55b4_queue_read (self);
  goodix55b4_schedule (self);
}

static void
goodix55b4_deactivate (FpImageDevice *device)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);
  self->cycle_start_pending = FALSE;
  if (self->session == NULL)
    {
      fpi_image_device_deactivate_complete (device, NULL);
      return;
    }
  self->deactivating = TRUE;
  if (goodix_session_capture_busy (self->session))
    {
      GoodixFingerAction action = self->finger_cycle != NULL ?
        goodix_finger_cycle_action (self->finger_cycle) :
        GOODIX_FINGER_ACTION_NONE;

      /* After an image is delivered, libfprint deactivates before the
       * finger-up tail has completed. Let that bounded tail reach sleep so
       * the reader is left idle. Earlier waits still need prompt cancellation. */
      if (action < GOODIX_FINGER_ACTION_FDT_UP)
        {
          if (self->finger_cycle != NULL)
            goodix_finger_cycle_disconnect (self->finger_cycle);
          goodix_session_fail (self->session, TRUE);
        }
    }
  else
    goodix_session_deactivate (self->session);
  goodix55b4_schedule (self);
}

static void
goodix55b4_change_state (FpImageDevice *device, FpiImageDeviceState state)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON ||
      self->session == NULL || self->closing || self->deactivating ||
      self->finger_cycle == NULL)
    return;
  /* Finger-off is reported at FDT-up, before refresh and sleep complete.
   * libfprint may request the next enrollment scan immediately; defer that
   * request instead of treating the still-running cleanup tail as busy. */
  self->cycle_start_pending = TRUE;
  goodix55b4_maybe_start_cycle (self);
}

static void
goodix55b4_start_capture_action (FpDevice *device)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);

  if (!GOODIX55B4_DEVELOPMENT ||
      (action == FPI_DEVICE_ACTION_CAPTURE && !GOODIX55B4_DEVELOPMENT_CAPTURE))
    {
      fpi_device_action_error (device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Biometric operations require an explicit research build"));
      return;
    }

  self->enroll_captured = 0;
  self->finish_action_on_idle = FALSE;
  self->cycle_start_pending = FALSE;
  if (action == FPI_DEVICE_ACTION_CAPTURE)
    {
      gboolean wait_for_finger;

      fpi_device_get_capture_data (device, &wait_for_finger);
      if (!wait_for_finger)
        {
          fpi_device_action_error (device,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          return;
        }
    }
  else if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      FpPrint *print;

      fpi_device_get_enroll_data (device, &print);
      fpi_print_set_type (print, FPI_PRINT_RAW);
    }
  fpi_image_device_activate (FP_IMAGE_DEVICE (device));
}

static const FpIdEntry goodix55b4_id_table[] = {
  { .vid = 0x27c6, .pid = 0x55b4 },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_goodix55b4_init (FpiDeviceGoodix55b4 *self)
{
  (void) self;
}

static void
fpi_device_goodix55b4_finalize (GObject *object)
{
  FpiDeviceGoodix55b4 *self = FPI_DEVICE_GOODIX55B4 (object);

  if (self->timer != NULL)
    g_source_destroy (self->timer);
  goodix55b4_clear_cycle (self);
  g_clear_pointer (&self->session, goodix_session_free);
  g_clear_object (&self->io_cancel);

  G_OBJECT_CLASS (fpi_device_goodix55b4_parent_class)->finalize (object);
}

static void
fpi_device_goodix55b4_class_init (FpiDeviceGoodix55b4Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *image_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_goodix55b4_finalize;

  device_class->id = "goodix55b4";
  device_class->full_name = "Goodix 27c6:55b4 Fingerprint Sensor";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = goodix55b4_id_table;
  /* The sensor is explicitly returned to sleep after every bounded capture,
   * including while one interactive enrollment action remains open. */
  device_class->temp_hot_seconds = -1;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  device_class->nr_enroll_stages = GOODIX55B4_ENROLL_STAGES;
  device_class->enroll = goodix55b4_start_capture_action;
  device_class->identify = goodix55b4_start_capture_action;
  device_class->verify = goodix55b4_start_capture_action;
  device_class->capture = goodix55b4_start_capture_action;

  image_class->img_open = goodix55b4_open;
  image_class->img_close = goodix55b4_close;
  image_class->activate = goodix55b4_activate;
  image_class->deactivate = goodix55b4_deactivate;
  image_class->change_state = goodix55b4_change_state;
  image_class->img_width = GOODIX_FORMAT_WIDTH * GOODIX55B4_IMAGE_SCALE;
  image_class->img_height = GOODIX_FORMAT_HEIGHT * GOODIX55B4_IMAGE_SCALE;
}
