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
#include <zephyr.h>
#include <zephyr/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
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

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_FW_UPDATE_H__ */
