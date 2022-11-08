/**
 * @file lcz_lwm2m_fw_update.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_FW_UPDATE_H__
#define __LCZ_LWM2M_FW_UPDATE_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stddef.h>
#include <zephyr/zephyr.h>
#include <zephyr/types.h>
#include <zephyr/net/lwm2m.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_SHELL)
/**
 * @brief Function to be called to check file permissions
 *
 * This callback function is used to notify the application about a pending file
 * read/write request through the firmware download shell. The callback can
 * authorize or deny the request.
 *
 * @param path		The path of the file to be accessed.
 * @param write		True if write access is requested, false for read access
 *
 * @return true to allow the operation, false to deny it
 */
typedef bool (*lcz_lwm2m_fw_update_shell_perm_cb_t)(const char *path, bool write);
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/

/**
 * @brief Set package name (resource 6)
 *
 * @param value package name
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_fw_update_set_pkg_name(char *value);

/**
 * @brief Set package version (resource 7)
 *
 * @param value package version
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_fw_update_set_pkg_version(char *value);

/**
 * @brief Set proxy server URI
 *
 * @param value proxy server url
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_fw_update_set_proxy_server(char *value);

/**
 * @brief Load credential information for a file transfer context
 *
 * @param[in] client_ctx LwM2M engine context to use
 * @return 0 on success, <0 or error
 */
int lcz_lwm2m_fw_update_load_certs(struct lwm2m_ctx * client_ctx);

#if defined(CONFIG_LCZ_LWM2M_FW_UPDATE_SHELL)
/**
 * @brief Register a permission callback for the firmware update shell
 *
 * @param[in] cb Callback to call when preparing to write a file
 */
void lcz_lwm2m_fw_update_shell_reg_perm_cb(lcz_lwm2m_fw_update_shell_perm_cb_t cb);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_FW_UPDATE_H__ */
