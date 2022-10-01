/**
 * @file lcz_lwm2m_fw_update_shell.c
 *
 * Copyright (c) 2022 Laird Connectivity LLC
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_fw_update_shell, CONFIG_LCZ_LWM2M_FW_UPDATE_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stdlib.h>
#include <shell/shell.h>
#include <lcz_lwm2m.h>

#include "file_system_utilities.h"
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
#include "encrypted_file_storage.h"
#endif
#include "lwm2m_pull_context.h"
#include "lcz_lwm2m_fw_update.h"

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static lcz_lwm2m_fw_update_shell_perm_cb_t perm_cb = NULL;

static char destination[FSU_MAX_ABS_PATH_SIZE + 1];
static int percent_complete;

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
int dl_write_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id, uint8_t *data,
		uint16_t data_len, bool last_block, size_t total_size)
{
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
    bool encrypted = false;
#endif
	int percent;
	int ret;

	/* Append the new data to the end of the file */
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
	encrypted = efs_is_encrypted_path(destination);
	if (encrypted) {
		ret = efs_append(destination, data, data_len);
	} else
#endif
    {
		ret = fsu_append_abs(destination, data, data_len);
	}
	if (ret < 0) {
		LOG_ERR("dl_write_cb: Append failed: %d", ret);
	} else if (ret != data_len) {
		LOG_ERR("dl_write_cb: Append didn't write enough bytes (expected %d, got %d)",
			data_len, ret);
	}

	/* Update percent complete */
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
    if (encrypted) {
	    percent = efs_get_file_size(destination);
    } else
#endif
    {
	    percent = fsu_get_file_size_abs(destination);
    }
    percent = (percent * 100) / total_size;
	if (percent != percent_complete) {
		LOG_INF("Downloaded %d%%", percent);
		percent_complete = percent;
	}

	return 0;
}

static void dl_result_cb(uint16_t obj_inst_id, int error_code)
{
	LOG_INF("File download result: %d", error_code);
}

static int shell_fw_dl(const struct shell *shell, size_t argc, char **argv)
{
	static struct requesting_object req = {
		.obj_inst_id = 0,
		.is_firmware_uri = true,
		.result_cb = dl_result_cb,
		.verify_cb = NULL,
		.write_cb = dl_write_cb,

	};
	int ret;

	/* Fill in the request structure fields */
	req.proxy_uri = lwm2m_firmware_get_proxy_uri();
	req.load_credentials = lwm2m_firmware_get_credential_cb();

	/* Use file system rules to validate the filename */
	if (perm_cb != NULL) {
		if (perm_cb(argv[1], true) == false) {
			shell_error(shell, "Permission denied to write %s", argv[1]);
			return -EPERM;
		}
	}

	/* Store the filename */
	memset(destination, 0, sizeof(destination));
	strncpy(destination, argv[1], sizeof(destination) - 1);

	/* Delete the file before starting */
	(void)fsu_delete_abs(destination);
	percent_complete = 0;

	/* start file transfer work */
	ret = lwm2m_pull_context_start_transfer(argv[2], req, K_NO_WAIT);
	if (ret < 0) {
		shell_error(shell, "Start download failed: %d", ret);
	} else {
		shell_print(shell, "Download started");
	}

	return ret;
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_lwm2m_fw_update_shell_reg_perm_cb(lcz_lwm2m_fw_update_shell_perm_cb_t cb)
{
	perm_cb = cb;
}

SHELL_STATIC_SUBCMD_SET_CREATE(fw_cmds,
			       SHELL_CMD_ARG(dl, NULL, "Download a file <local> <url>", shell_fw_dl,
					     3, 0),
			       SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(fw, &fw_cmds, "Firmware update commands", NULL);
