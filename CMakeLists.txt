#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

zephyr_include_directories(include)

if(CONFIG_LCZ_LWM2M_FW_UPDATE)

zephyr_sources(src/lcz_lwm2m_fw_update.c)

endif()
