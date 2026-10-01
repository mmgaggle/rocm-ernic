# Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
#
# SPDX-License-Identifier: MIT

# libuet_ernic: the UEC reference provider's uet_api.h subset that the
# libfabric "uet" provider calls, implemented over libibverbs and the UET
# engine's command channel (shared/uet_ernic_abi.h). It runs in the guest;
# building it here keeps it compiling and lets its test run against a fake
# libibverbs (tests/CMakeLists.txt).
#
# It takes struct uet_addr from the reference provider tree and libfabric's
# types from libfabric's installed headers, and links only libibverbs.

if(NOT LIBFABRIC_FOUND)
    message(STATUS "libfabric headers not found: not building libuet_ernic")
    return()
endif()

set(ERNIC_UET_GUEST_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libuet_ernic
    PARENT_SCOPE)

add_library(uet_ernic SHARED libuet_ernic/uet_ernic.c)
target_include_directories(uet_ernic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libuet_ernic
    ${CMAKE_SOURCE_DIR}/shared
)
target_include_directories(uet_ernic SYSTEM PRIVATE
    ${ERNIC_UET_SOURCE_DIR}
    ${LIBFABRIC_INCLUDE_DIRS}
    ${ERNIC_IBVERBS_INCLUDE_DIRS}
)
target_compile_definitions(uet_ernic PRIVATE _GNU_SOURCE)
target_link_directories(uet_ernic PRIVATE ${IBVERBS_LIBRARY_DIRS})
target_link_libraries(uet_ernic PRIVATE ${IBVERBS_LIBRARIES} pthread)
set_target_properties(uet_ernic PROPERTIES VERSION 0.1.0 SOVERSION 0)
ernic_set_compiler_flags(uet_ernic)
if(ERNIC_WERROR)
    target_compile_options(uet_ernic PRIVATE -Werror)
endif()

# uet_ernic.h repeats the reference's declarations; compiling it together
# with uet_api.h makes any drift a build failure. uet_api.h needs the
# libfabric headers bundled with the reference, not the installed ones.
add_library(uet_ernic_abi_check OBJECT libuet_ernic/abi_check.c)
target_include_directories(uet_ernic_abi_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libuet_ernic
)
target_include_directories(uet_ernic_abi_check SYSTEM PRIVATE
    ${ERNIC_UET_SOURCE_DIR}
    ${ERNIC_UET_SOURCE_DIR}/nic_shim
    ${ERNIC_UET_SOURCE_DIR}/libfabric_headers
    ${ERNIC_UET_SOURCE_DIR}/libfabric_headers/include
)
target_compile_definitions(uet_ernic_abi_check PRIVATE
    _GNU_SOURCE
    ENABLE_VERBS=0
)
target_compile_options(uet_ernic_abi_check PRIVATE -Werror)

# The phase 3 workload: Slice A between two guests, through the library.
add_executable(uet_ernic_rma tools/uet_ernic_rma.c)
target_include_directories(uet_ernic_rma PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libuet_ernic
)
target_include_directories(uet_ernic_rma SYSTEM PRIVATE
    ${ERNIC_UET_SOURCE_DIR}
    ${LIBFABRIC_INCLUDE_DIRS}
)
target_compile_definitions(uet_ernic_rma PRIVATE _GNU_SOURCE)
target_link_libraries(uet_ernic_rma PRIVATE uet_ernic)
ernic_set_compiler_flags(uet_ernic_rma)
if(ERNIC_WERROR)
    target_compile_options(uet_ernic_rma PRIVATE -Werror)
endif()
