cmake_minimum_required(VERSION 3.21.0 FATAL_ERROR)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
	cmake_policy(SET CMP0135 NEW)
endif()

set(PROJECT_NAME                    "${PARAM_PROJECT_NAME}")
set(${PROJECT_NAME}_SUMMARY         "${PARAM_PROJECT_SUMMARY}")
set(${PROJECT_NAME}_VERSION_MAJOR   "${PARAM_PROJECT_VERSION_MAJOR}")
set(${PROJECT_NAME}_VERSION_MINOR   "${PARAM_PROJECT_VERSION_MINOR}")
set(${PROJECT_NAME}_VERSION_PATCH   "${PARAM_PROJECT_VERSION_PATCH}")
set(${PROJECT_NAME}_VERSION         "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}.${${PROJECT_NAME}_VERSION_PATCH}")
set(${PROJECT_NAME}_ARCHITECTURE    "${PARAM_PROJECT_ARCHITECTURE}")
set(${PROJECT_NAME}_LIMINE_API_REV  "${PARAM_PROJECT_LIMINE_API_REV}")
set(${PROJECT_NAME}_ISO_DIR         "${PARAM_PROJECT_ISO_DIR}")
set(${PROJECT_NAME}_C_STD           "${PARAM_PROJECT_C_STANDARD_VERSION}")
set(${PROJECT_NAME}_CXX_STD         "${PARAM_PROJECT_CXX_STANDARD_VERSION}")
set(${PROJECT_NAME}_QEMU_VNC        "${PARAM_PROJECT_QEMU_VNC}")
set(${PROJECT_NAME}_USE_LLVM_LIBC   "${PARAM_PROJECT_USE_LLVM_LIBC}")
set(${PROJECT_NAME}_ISO_FILE        "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.iso")

project(
    "${PARAM_PROJECT_NAME}"
    VERSION "${${PROJECT_NAME}_VERSION}"
    DESCRIPTION "${${PROJECT_NAME}_SUMMARY}"
    LANGUAGES C CXX ASM
)

# set(CMAKE_C_STANDARD ${${PROJECT_NAME}_C_STD})
# set(CMAKE_CXX_STANDARD ${${PROJECT_NAME}_CXX_STD})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/compiler/Flags.cmake)
include(cmake/compiler/Cache.cmake)
include(cmake/compiler/Linker.cmake)

include(cmake/misc/ProjectOptions.cmake)
include(cmake/misc/PreventInSourceBuilds.cmake)
include(cmake/misc/CheckAndApplyFlags.cmake)
include(cmake/misc/AddSource.cmake)
include(cmake/misc/Utils.cmake)
include(cmake/misc/IsoBuilder.cmake)

include(cmake/docs/Doxygen.cmake)
include(cmake/emulator/Qemu.cmake)

include(cmake/deps/CPM.cmake)
include(cmake/deps/Limine.cmake)
include(cmake/deps/Ovmf.cmake)
include(cmake/deps/Klibc.cmake)
# include(cmake/deps/FreestndCxxHdrs.cmake)
include(cmake/deps/Uacpi.cmake)

include(cmake/analyze/ClangTidy.cmake)
include(cmake/format/ClangFormat.cmake)

project_enable_cache()
project_configure_linker()
project_assure_out_of_source_builds()

if(${PROJECT_NAME}_USE_LLVM_LIBC)
    setup_prebuilt_klibc()
endif()

message(STATUS "Freestnd hdrs at ${FREESTND_HDRS_DIR}")

include(${uacpi_SOURCE_DIR}/uacpi.cmake)

# add_subdirectory(klibc)
add_subdirectory(kernel)
add_subdirectory(misc/limine)
add_subdirectory(userland)

# project_enable_doxygen("awesome-sidebar")

build_iso(
    TRIGGER_NAME "iso"
    STAGING_DIR ${${PROJECT_NAME}_ISO_DIR}
    XORRISO_FLAGS ${XORRISO_FLAGS}
)

setup_limine()
add_qemu_targets(
    ISO_FILE ${${PROJECT_NAME}_ISO_FILE}
    COMMON_FLAGS ${QEMU_COMMON_FLAGS}
    ACCEL_FLAGS ${QEMU_HARDWARE_ACCEL_FLAGS}
    DEBUG_FLAGS ${QEMU_DEBUG_FLAGS}
)

set(
    SOURCE_DIRECTORIES
    "${CMAKE_SOURCE_DIR}/kernel"
    "${CMAKE_SOURCE_DIR}/userland"
)

add_clang_format_target(
    TARGET_NAME "format"
    DIRECTORIES ${SOURCE_DIRECTORIES}
)

add_clang_tidy_target(
    TARGET_NAME "tidy"
    DIRECTORIES ${SOURCE_DIRECTORIES}
)