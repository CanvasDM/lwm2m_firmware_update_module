/**
 * @file lcz_lwm2m_fw_update.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_fw_update, CONFIG_LCZ_LWM2M_FW_UPDATE_LOG_LEVEL);

#include <zephyr.h>
#include <init.h>
#include <sys/reboot.h>
#include <dfu/mcuboot.h>
#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#include <logging/log_ctrl.h>
#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_PKI)
#include <lcz_pki_auth.h>
#endif

#include "lcz_lwm2m_client.h"
#include "lcz_lwm2m_fw_update.h"
#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_ATTRIBUTES)
#include "attr.h"
#endif

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define BYTE_PROGRESS_STEP (1024 * 10)
#define REBOOT_DELAY K_SECONDS(CONFIG_LCZ_LWM2M_FW_UPDATE_REBOOT_DELAY_SECONDS)
#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_COAP_PROXY_SUPPORT)
#define FIRMWARE_UPDATE_PROTOCOL_INST_0 "5/0/8/0"
#define FW_UPDATE_PROTO_COAPS 1
#define FW_DELIVERY_PULL_ONLY 0
#endif
/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static uint8_t __aligned(4) mcuboot_buf[CONFIG_LCZ_LWM2M_FW_UPDATE_MCUBOOT_FLASH_BUF_SIZE];
static uint8_t firmware_data_buf[CONFIG_LCZ_LWM2M_COAP_BLOCK_SIZE];
static uint8_t percent_downloaded = 0;
static uint32_t bytes_downloaded = 0;
static int image_type = DFU_TARGET_IMAGE_TYPE_ANY;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void *lwm2m_fw_prewrite_callback(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
					size_t *data_len);
static int lwm2m_fw_block_received_callback(uint16_t obj_inst_id, uint16_t res_id,
					    uint16_t res_inst_id, uint8_t *data, uint16_t data_len,
					    bool last_block, size_t total_size);
static int lwm2m_fw_update_callback(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static void lwm2m_set_fw_update_state(int state);
static void lwm2m_set_fw_update_result(int result);
static void dfu_target_cb(enum dfu_target_evt_id evt);
static int lcz_lwm2m_fw_update_init(const struct device *device);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void *lwm2m_fw_prewrite_callback(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
					size_t *data_len)
{
	*data_len = sizeof(firmware_data_buf);
	return firmware_data_buf;
}

static int lwm2m_fw_block_received_callback(uint16_t obj_inst_id, uint16_t res_id,
					    uint16_t res_inst_id, uint8_t *data, uint16_t data_len,
					    bool last_block, size_t total_size)
{
	uint8_t curent_percent;
	uint32_t current_bytes;
	size_t offset;
	size_t skip = 0;
	int ret = 0;

	if (!data_len) {
		LOG_ERR("Data len is zero, nothing to write.");
		return -EINVAL;
	}

	if (bytes_downloaded == 0) {
		image_type = dfu_target_img_type(data, data_len);

		ret = dfu_target_init(image_type, 0, total_size, dfu_target_cb);
		if (ret < 0) {
			LOG_ERR("Failed to init DFU target, err: %d", ret);
			lwm2m_set_fw_update_state(STATE_IDLE);
			lwm2m_set_fw_update_result(RESULT_UPDATE_FAILED);
			goto cleanup;
		}

		LOG_INF("Firmware download started.");
		lwm2m_set_fw_update_state(STATE_DOWNLOADING);
	}

	ret = dfu_target_offset_get(&offset);
	if (ret < 0) {
		LOG_ERR("Failed to obtain current offset, err: %d", ret);
		lwm2m_set_fw_update_state(STATE_IDLE);
		lwm2m_set_fw_update_result(RESULT_UPDATE_FAILED);
		goto cleanup;
	}

	/* Display a % downloaded or byte progress, if no total size was
	 * provided (this can happen in PULL mode FOTA)
	 */
	if (total_size > 0) {
		curent_percent = bytes_downloaded * 100 / total_size;
		if (curent_percent > percent_downloaded) {
			percent_downloaded = curent_percent;
			LOG_INF("Downloaded %d%%", percent_downloaded);
		}
	} else {
		current_bytes = bytes_downloaded + data_len;
		if (current_bytes / BYTE_PROGRESS_STEP > bytes_downloaded / BYTE_PROGRESS_STEP) {
			LOG_INF("Downloaded %d KB", current_bytes / 1024);
		}
	}

	if (bytes_downloaded < offset) {
		skip = MIN(data_len, offset - bytes_downloaded);

		LOG_INF("Skipping bytes %d-%d, already written.", bytes_downloaded,
			bytes_downloaded + skip);
	}

	bytes_downloaded += data_len;

	if (skip == data_len) {
		/* Nothing to do. */
		return 0;
	}

	ret = dfu_target_write(data + skip, data_len - skip);
	if (ret < 0) {
		LOG_ERR("dfu_target_write error, err %d", ret);
		lwm2m_set_fw_update_state(STATE_IDLE);
		lwm2m_set_fw_update_result(RESULT_UPDATE_FAILED);
		goto cleanup;
	}

	if (!last_block) {
		/* Keep going */
		return 0;
	} else {
		ret = dfu_target_done(true);
		if (ret == 0) {
			ret = dfu_target_schedule_update(0);
		}
		if (ret < 0) {
			LOG_ERR("Could not schedule update [%d]", ret);
			goto cleanup;
		}
		LOG_INF("Firmware downloaded, %d bytes in total", bytes_downloaded);
	}

	if (total_size && (bytes_downloaded != total_size)) {
		LOG_ERR("Early last block, downloaded %d, expecting %d", bytes_downloaded,
			total_size);
		ret = -EIO;
		lwm2m_set_fw_update_state(STATE_IDLE);
		lwm2m_set_fw_update_result(RESULT_UPDATE_FAILED);
	}

cleanup:
	if (ret < 0) {
		if (dfu_target_reset() < 0) {
			LOG_ERR("Failed to reset DFU target");
		}
	}

	bytes_downloaded = 0;
	percent_downloaded = 0;

	return ret;
}

static int lwm2m_fw_update_callback(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	ARG_UNUSED(args);
	ARG_UNUSED(args_len);

	LOG_INF("Executing firmware update");
	lwm2m_set_fw_update_state(STATE_UPDATING);
	lcz_lwm2m_client_reboot();

	return 0;
}

static void lwm2m_set_fw_update_state(int state)
{
	lwm2m_engine_set_u8("5/0/3", (uint8_t)state);
}

static void lwm2m_set_fw_update_result(int result)
{
	lwm2m_engine_set_u8("5/0/5", result);
}

static void dfu_target_cb(enum dfu_target_evt_id evt)
{
	ARG_UNUSED(evt);
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_lwm2m_fw_update_set_pkg_name(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_fup_pkg_name, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("5/0/6/0", value, strlen(value) + 1,
					LWM2M_RES_DATA_FLAG_RO);
	if (ret < 0) {
		goto exit;
	}
exit:
	return ret;
}

int lcz_lwm2m_fw_update_set_pkg_version(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_fup_pkg_ver, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("5/0/7/0", value, strlen(value) + 1,
					LWM2M_RES_DATA_FLAG_RO);
	if (ret < 0) {
		goto exit;
	}
exit:
	return ret;
}

#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_COAP_PROXY_SUPPORT)
int lcz_lwm2m_fw_update_set_proxy_server(char *value)
{
	int ret = 0;

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_fup_proxy_srv, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif

	lwm2m_firmware_set_proxy_uri(value);

exit:
	return ret;
}
#endif

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_PKI)
int lcz_lwm2m_fw_update_load_certs(struct lwm2m_ctx *client_ctx)
{
	return lcz_pki_auth_tls_credential_load(LCZ_PKI_AUTH_STORE_FILE_SERVICE,
						client_ctx->tls_tag, false);
}
#endif /* CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_PKI */

SYS_INIT(lcz_lwm2m_fw_update_init, APPLICATION, CONFIG_LCZ_LWM2M_FW_UPDATE_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_fw_update_init(const struct device *device)
{
	int ret;
	char *pkg_name;
	char *pkg_ver;
#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_COAP_PROXY_SUPPORT)
	char *proxy_server;
	static uint8_t delivery_method;
#endif
	bool image_ok;

	ARG_UNUSED(device);

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_INIT_KCONFIG)
	pkg_name = CONFIG_LCZ_LWM2M_FW_UPDATE_PKG_NAME;
	pkg_ver = CONFIG_LCZ_LWM2M_FW_UPDATE_PKG_VERSION;
#else
	pkg_name = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_fup_pkg_name);
	pkg_ver = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_fup_pkg_ver);
#endif

#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_COAP_PROXY_SUPPORT)
#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_INIT_KCONFIG)
	proxy_server = CONFIG_LCZ_LWM2M_FW_UPDATE_PROXY_URL;
#else
	proxy_server = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_fup_proxy_srv);
#endif
#endif

	/* Setup data buffer for block-wise transfer */
	lwm2m_engine_register_pre_write_callback("5/0/0", lwm2m_fw_prewrite_callback);
	lwm2m_firmware_set_write_cb(lwm2m_fw_block_received_callback);
#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_SUPPORT)
	lwm2m_firmware_set_update_cb(lwm2m_fw_update_callback);
#endif
#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_ENABLE_PKI)
	lwm2m_firmware_set_credential_cb(lcz_lwm2m_fw_update_load_certs);
#endif

	ret = lcz_lwm2m_fw_update_set_pkg_name(pkg_name);
	if (ret < 0) {
		LOG_ERR("Could not set pkg name [%d]", ret);
		goto exit;
	}

	ret = lcz_lwm2m_fw_update_set_pkg_version(pkg_ver);
	if (ret < 0) {
		LOG_ERR("Could not set pkg version [%d]", ret);
		goto exit;
	}

#if defined(CONFIG_LCZ_LWM2M_FIRMWARE_UPDATE_PULL_COAP_PROXY_SUPPORT)
	ret = lcz_lwm2m_fw_update_set_proxy_server(proxy_server);
	if (ret < 0) {
		LOG_ERR("Could not set proxy server [%d]", ret);
		goto exit;
	}
	delivery_method = FW_UPDATE_PROTO_COAPS;
	(void)lwm2m_engine_create_res_inst(FIRMWARE_UPDATE_PROTOCOL_INST_0);
	(void)lwm2m_engine_set_res_data(FIRMWARE_UPDATE_PROTOCOL_INST_0, &delivery_method,
					sizeof(delivery_method), LWM2M_RES_DATA_FLAG_RO);
	(void)lwm2m_engine_set_u8("5/0/9", FW_DELIVERY_PULL_ONLY);
#endif

	/* Set the required buffer for MCUboot targets */
	ret = dfu_target_mcuboot_set_buf(mcuboot_buf, sizeof(mcuboot_buf));
	if (ret) {
		LOG_ERR("Failed to set MCUboot flash buffer %d", ret);
		goto exit;
	}

	image_ok = boot_is_img_confirmed();
	LOG_INF("Image is%s confirmed", image_ok ? "" : " not");
	if (!image_ok) {
		ret = boot_write_img_confirmed();
		if (ret) {
			LOG_ERR("Couldn't confirm this image: %d", ret);
			lwm2m_set_fw_update_state(STATE_IDLE);
			lwm2m_set_fw_update_result(RESULT_UPDATE_FAILED);
		} else {
			LOG_INF("Marked image as OK");
			lwm2m_set_fw_update_state(STATE_IDLE);
			lwm2m_set_fw_update_result(RESULT_SUCCESS);
		}
	}

	LOG_DBG("LwM2M firmware update initialized");
exit:
	return ret;
}
