# Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
#
# SPDX-License-Identifier: MIT

# Optional UET engine
#
# The engine (src/uet_engine.c, src/uet_nic_ernic.c) runs the UEC reference
# provider's SES, PDS and TSS sublayers inside the server. It links the
# provider's ENABLE_VERBS=1 static library, libuet_verbs.a, which has no
# runtime libfabric dependency, and needs the device-model hooks (an
# external NIC shim, a non-blocking next-hop resolver, a DMA translator and
# per-endpoint RUDI selection) that the provider gained for it.
#
#   cmake -B build -DERNIC_UET=ON -DERNIC_UET_SOURCE_DIR=/path/to/uet-ref-prov
#
# By default the archive is built in the provider's tree with its own
# Makefile ("make libuet_verbs.a") as part of every build, which is a no-op
# when it is up to date. Set ERNIC_UET_LIBRARY to link a prebuilt archive
# instead.
#
# ERNIC_UET_DPDK adds a DPDK port as an alternative wire for the engine
# (--uet ...,wire=dpdk,dpdk-dev=..., src/uet_wire_dpdk.c). It needs
# libdpdk (pkg-config); the default build does not.

option(ERNIC_UET
  "Build the UET engine on the UEC reference provider (--uet)"
  OFF)
option(ERNIC_UET_DPDK
  "Build the UET engine's DPDK wire backend (needs libdpdk)"
  OFF)
set(ERNIC_UET_SOURCE_DIR "" CACHE PATH
  "UEC reference provider source tree (uet-ref-prov)")
set(ERNIC_UET_LIBRARY "" CACHE FILEPATH
  "Prebuilt libuet_verbs.a; empty to build it in ERNIC_UET_SOURCE_DIR")

set(ERNIC_UET_SOURCES
    src/uet_engine.c
    src/uet_nic_ernic.c
    src/uet_svc.c
)

if(ERNIC_UET)
    if(NOT ERNIC_UET_SOURCE_DIR)
        message(FATAL_ERROR
          "ERNIC_UET=ON needs ERNIC_UET_SOURCE_DIR, the UEC reference "
          "provider source tree")
    endif()

    foreach(header uet_api.h uet_addr.h uet_pkt_hdr.h nic_shim/uet_nic.h)
        if(NOT EXISTS "${ERNIC_UET_SOURCE_DIR}/${header}")
            message(FATAL_ERROR
              "${ERNIC_UET_SOURCE_DIR} is not a UEC reference provider "
              "tree: ${header} is missing")
        endif()
    endforeach()

    # The device-model hooks are not in every version of the provider:
    # the shim and translator (wip-ernic-hooks), and the wire information,
    # transmit in pieces and copy engine (wip-uet-perf).
    file(STRINGS "${ERNIC_UET_SOURCE_DIR}/nic_shim/uet_nic.h"
      ernic_uet_shim_hook REGEX "uet_nic_register_shim")
    file(STRINGS "${ERNIC_UET_SOURCE_DIR}/nic_shim/uet_nic.h"
      ernic_uet_iov_hook REGEX "nic_tx_pkt_iov")
    file(STRINGS "${ERNIC_UET_SOURCE_DIR}/uet_api.h"
      ernic_uet_dma_hook REGEX "uet_set_dma_translate")
    file(STRINGS "${ERNIC_UET_SOURCE_DIR}/uet_api.h"
      ernic_uet_wire_hook REGEX "uet_get_wire_info")
    if(NOT ernic_uet_shim_hook OR NOT ernic_uet_dma_hook OR
       NOT ernic_uet_wire_hook OR NOT ernic_uet_iov_hook)
        message(FATAL_ERROR
          "${ERNIC_UET_SOURCE_DIR} lacks the device-model hooks "
          "(uet_nic_register_shim, uet_set_dma_translate, "
          "uet_get_wire_info, nic_tx_pkt_iov) the engine needs")
    endif()

    if(ERNIC_UET_DPDK)
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
        list(APPEND ERNIC_UET_SOURCES src/uet_wire_dpdk.c)
        # The DPDK headers want their own flags (-include rte_config.h,
        # -march), and the experimental API for buffer split and flow
        # isolation; only this file includes them.
        set_source_files_properties(src/uet_wire_dpdk.c PROPERTIES
          COMPILE_OPTIONS "${DPDK_CFLAGS_OTHER};-DALLOW_EXPERIMENTAL_API")
    endif()

    # The guest library (guest/) uses libfabric's types, not the library,
    # so only the headers are needed; without them it is not built.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBFABRIC libfabric)

    set(ERNIC_UET_INCLUDE_DIRS
        ${ERNIC_UET_SOURCE_DIR}
        ${ERNIC_UET_SOURCE_DIR}/nic_shim
        ${ERNIC_UET_SOURCE_DIR}/libfabric_headers
        ${ERNIC_UET_SOURCE_DIR}/libfabric_headers/include
    )

    if(ERNIC_UET_LIBRARY)
        set(ERNIC_UET_ARCHIVE "${ERNIC_UET_LIBRARY}")
        add_custom_target(ernic_uet_verbs)
    else()
        find_program(ERNIC_UET_MAKE NAMES gmake make REQUIRED)
        set(ERNIC_UET_ARCHIVE "${ERNIC_UET_SOURCE_DIR}/libuet_verbs.a")
        add_custom_target(ernic_uet_verbs
            COMMAND ${ERNIC_UET_MAKE} -C ${ERNIC_UET_SOURCE_DIR} libuet_verbs.a
            BYPRODUCTS ${ERNIC_UET_ARCHIVE}
            COMMENT "Building libuet_verbs.a in ${ERNIC_UET_SOURCE_DIR}"
            VERBATIM
        )
    endif()
endif()

# Compile and link a target against the provider.
function(ernic_uet_link target)
    target_include_directories(${target} SYSTEM PRIVATE
        ${ERNIC_UET_INCLUDE_DIRS}
    )
    target_compile_definitions(${target} PRIVATE
        ERNIC_HAVE_UET=1
        ENABLE_VERBS=1
    )
    target_link_libraries(${target} PRIVATE ${ERNIC_UET_ARCHIVE} pthread)
    add_dependencies(${target} ernic_uet_verbs)
    if(ERNIC_UET_DPDK)
        target_include_directories(${target} SYSTEM PRIVATE
            ${DPDK_INCLUDE_DIRS})
        target_compile_definitions(${target} PRIVATE ERNIC_HAVE_UET_DPDK=1)
        target_link_libraries(${target} PRIVATE PkgConfig::DPDK)
    endif()
endfunction()
