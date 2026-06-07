cmake_minimum_required(VERSION 3.21.0 FATAL_ERROR)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

if(NOT DEFINED PARAM_PROJECT_NAME OR "${PARAM_PROJECT_NAME}" STREQUAL "")
    set(PARAM_PROJECT_NAME "Hazel")
endif()

if(NOT DEFINED PARAM_PROJECT_SUMMARY OR "${PARAM_PROJECT_SUMMARY}" STREQUAL "")
    set(PARAM_PROJECT_SUMMARY "Kernel")
endif()

if(NOT DEFINED PARAM_PROJECT_VERSION_MAJOR OR "${PARAM_PROJECT_VERSION_MAJOR}" STREQUAL "")
    set(PARAM_PROJECT_VERSION_MAJOR "0")
endif()

if(NOT DEFINED PARAM_PROJECT_VERSION_MINOR OR "${PARAM_PROJECT_VERSION_MINOR}" STREQUAL "")
    set(PARAM_PROJECT_VERSION_MINOR "0")
endif()

if(NOT DEFINED PARAM_PROJECT_VERSION_PATCH OR "${PARAM_PROJECT_VERSION_PATCH}" STREQUAL "")
    set(PARAM_PROJECT_VERSION_PATCH "1")
endif()

if(
    NOT DEFINED PARAM_PROJECT_C_STANDARD_VERSION
    OR "${PARAM_PROJECT_C_STANDARD_VERSION}" STREQUAL ""
)
    set(PARAM_PROJECT_C_STANDARD_VERSION "2Y")
endif()

if(
    NOT DEFINED PARAM_PROJECT_CXX_STANDARD_VERSION
    OR "${PARAM_PROJECT_CXX_STANDARD_VERSION}" STREQUAL ""
)
    set(PARAM_PROJECT_CXX_STANDARD_VERSION "26")
endif()

if(NOT DEFINED PARAM_PROJECT_LIMINE_API_REV OR "${PARAM_PROJECT_LIMINE_API_REV}" STREQUAL "")
    set(PARAM_PROJECT_LIMINE_API_REV "6")
endif()

if(NOT DEFINED PARAM_PROJECT_ARCHITECTURE OR "${PARAM_PROJECT_ARCHITECTURE}" STREQUAL "")
    set(PARAM_PROJECT_ARCHITECTURE "x86_64")
endif()

if(NOT DEFINED PARAM_PROJECT_MAX_CPUS OR "${PARAM_PROJECT_MAX_CPUS}" STREQUAL "")
    set(PARAM_PROJECT_MAX_CPUS "32")
endif()

if(NOT DEFINED PARAM_PROJECT_USE_LLVM_LIBC OR "${PARAM_PROJECT_USE_LLVM_LIBC}" STREQUAL "")
    set(PARAM_PROJECT_USE_LLVM_LIBC ON)
endif()

if(NOT DEFINED PARAM_PROJECT_ENABLE_KASLR OR "${PARAM_PROJECT_ENABLE_KASLR}" STREQUAL "")
    set(PARAM_PROJECT_ENABLE_KASLR ON)
endif()

if(NOT DEFINED PARAM_PROJECT_ISO_DIR OR "${PARAM_PROJECT_ISO_DIR}" STREQUAL "")
    set(PARAM_PROJECT_ISO_DIR "${CMAKE_BINARY_DIR}/iso")
endif()

set(PROJECT_NAME "${PARAM_PROJECT_NAME}")
set(${PROJECT_NAME}_SUMMARY "${PARAM_PROJECT_SUMMARY}")
set(${PROJECT_NAME}_VERSION_MAJOR "${PARAM_PROJECT_VERSION_MAJOR}")
set(${PROJECT_NAME}_VERSION_MINOR "${PARAM_PROJECT_VERSION_MINOR}")
set(${PROJECT_NAME}_VERSION_PATCH "${PARAM_PROJECT_VERSION_PATCH}")
set(${PROJECT_NAME}_VERSION
    "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}.${${PROJECT_NAME}_VERSION_PATCH}"
)
set(${PROJECT_NAME}_ARCHITECTURE "${PARAM_PROJECT_ARCHITECTURE}")
set(${PROJECT_NAME}_MAX_CPUS "${PARAM_PROJECT_MAX_CPUS}")
set(${PROJECT_NAME}_LIMINE_API_REV "${PARAM_PROJECT_LIMINE_API_REV}")
set(${PROJECT_NAME}_ISO_DIR "${PARAM_PROJECT_ISO_DIR}")
set(${PROJECT_NAME}_C_STD "${PARAM_PROJECT_C_STANDARD_VERSION}")
set(${PROJECT_NAME}_CXX_STD "${PARAM_PROJECT_CXX_STANDARD_VERSION}")
set(${PROJECT_NAME}_QEMU_VNC "${PARAM_PROJECT_QEMU_VNC}")
set(${PROJECT_NAME}_USE_LLVM_LIBC "${PARAM_PROJECT_USE_LLVM_LIBC}")
set(${PROJECT_NAME}_ENABLE_KASLR "${PARAM_PROJECT_ENABLE_KASLR}")
set(${PROJECT_NAME}_ISO_FILE "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.iso")

project(
    "${PARAM_PROJECT_NAME}"
    VERSION "${${PROJECT_NAME}_VERSION}"
    DESCRIPTION "${${PROJECT_NAME}_SUMMARY}"
    LANGUAGES C CXX ASM
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/misc/ProjectOptions.cmake)
include(cmake/compiler/Compiler.cmake)

project_apply_default_options()
project_validate_compiler_support()
project_configure_language_standards()

include(cmake/compiler/Flags.cmake)
include(cmake/compiler/Cache.cmake)
include(cmake/compiler/Linker.cmake)
include(cmake/compiler/LTO.cmake)

include(cmake/misc/PreventInSourceBuilds.cmake)
include(cmake/misc/CheckAndApplyFlags.cmake)
include(cmake/misc/AddSource.cmake)
include(cmake/misc/Utils.cmake)
include(cmake/misc/IsoBuilder.cmake)
include(cmake/misc/ComponentProject.cmake)

include(cmake/docs/Doxygen.cmake)
include(cmake/emulator/Qemu.cmake)

include(cmake/deps/CPM.cmake)
include(cmake/deps/Limine.cmake)
include(cmake/deps/Ovmf.cmake)
include(cmake/deps/Uacpi.cmake)
include(cmake/deps/FreestndLibs.cmake)
include(cmake/deps/Flanterm.cmake)
include(cmake/deps/Klibc.cmake)

include(cmake/analyze/ClangTidy.cmake)
include(cmake/format/ClangFormat.cmake)

project_append_compiler_diagnostic_flags()
project_enable_cache()
project_configure_linker()
project_configure_lto()
project_assure_out_of_source_builds()

setup_ovmf()
setup_uacpi()
setup_freestnd_cxx_headers()
setup_flanterm()
setup_klibc()

include(${uacpi_SOURCE_DIR}/uacpi.cmake)

set(HAZEL_SUPERPROJECT_NAME "${PROJECT_NAME}")
set(HAZEL_SUPERPROJECT_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
set(HAZEL_SUPERPROJECT_BINARY_DIR "${CMAKE_BINARY_DIR}")

add_subdirectory(common)
add_subdirectory(kernel)
add_subdirectory(misc/limine)
add_subdirectory(userland)

if(NOT DEFINED HAZEL_KERNEL_TARGET OR "${HAZEL_KERNEL_TARGET}" STREQUAL "")
    set(HAZEL_KERNEL_TARGET kernel_final)
endif()
if(NOT TARGET ${HAZEL_KERNEL_TARGET})
    message(
        FATAL_ERROR
        "Kernel component did not export a valid target. Got '${HAZEL_KERNEL_TARGET}'."
    )
endif()

if(NOT DEFINED HAZEL_USERLAND_TARGET OR "${HAZEL_USERLAND_TARGET}" STREQUAL "")
    set(HAZEL_USERLAND_TARGET userland)
endif()
if(NOT TARGET ${HAZEL_USERLAND_TARGET})
    message(
        FATAL_ERROR
        "Userland component did not export a valid target. Got '${HAZEL_USERLAND_TARGET}'."
    )
endif()

setup_limine()
project_enable_doxygen()

build_iso(
    TRIGGER_NAME "iso"
    STAGING_DIR ${${PROJECT_NAME}_ISO_DIR}
    ARCHITECTURE ${${PROJECT_NAME}_ARCHITECTURE}
    DEPENDS ${HAZEL_KERNEL_TARGET} ${HAZEL_USERLAND_TARGET} install_limine
)

add_qemu_targets(ISO_FILE ${${PROJECT_NAME}_ISO_FILE} ARCHITECTURE ${${PROJECT_NAME}_ARCHITECTURE})

set(SOURCE_DIRECTORIES "${CMAKE_SOURCE_DIR}/kernel" "${CMAKE_SOURCE_DIR}/userland")

add_clang_format_target(TARGET_NAME "format" DIRECTORIES ${SOURCE_DIRECTORIES})

add_clang_tidy_target(TARGET_NAME "tidy" DIRECTORIES ${SOURCE_DIRECTORIES})
