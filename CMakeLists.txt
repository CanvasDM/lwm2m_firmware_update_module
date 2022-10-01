#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

zephyr_include_directories(include)

if(CONFIG_LCZ_LWM2M_FW_UPDATE)

zephyr_sources(src/lcz_lwm2m_fw_update.c)
zephyr_sources_ifdef(CONFIG_LCZ_LWM2M_FW_UPDATE_SHELL
    src/lcz_lwm2m_fw_update_shell.c)

endif()
