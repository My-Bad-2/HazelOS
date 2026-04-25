include_guard()

include(CMakeParseArguments)

set(HAZEL_QEMU_MEMORY "512M" CACHE STRING "RAM size passed to QEMU.")
set(HAZEL_QEMU_SMP "2" CACHE STRING "Virtual CPU count passed to QEMU.")
set(HAZEL_QEMU_SERIAL "stdio" CACHE STRING "QEMU serial backend.")
set(HAZEL_QEMU_RTC_BASE "localtime" CACHE STRING "QEMU RTC base setting.")

function(_hazel_qemu_binary_candidates out_var architecture)
    string(TOLOWER "${architecture}" _hazel_qemu_arch)
    if(_hazel_qemu_arch STREQUAL "amd64")
        set(_hazel_qemu_arch "x86_64")
    elseif(_hazel_qemu_arch STREQUAL "arm64")
        set(_hazel_qemu_arch "aarch64")
    endif()

    set(_hazel_candidates "qemu-system-${_hazel_qemu_arch}")
    if(_hazel_qemu_arch STREQUAL "x86_64")
        list(APPEND _hazel_candidates qemu-system-x86_64)
    elseif(_hazel_qemu_arch STREQUAL "aarch64")
        list(APPEND _hazel_candidates qemu-system-aarch64)
    endif()

    list(REMOVE_DUPLICATES _hazel_candidates)
    set(${out_var} "${_hazel_candidates}" PARENT_SCOPE)
endfunction()

function(_hazel_qemu_arch_machine_flags out_var architecture)
    string(TOLOWER "${architecture}" _hazel_qemu_arch)
    set(_hazel_flags "")

    if(_hazel_qemu_arch STREQUAL "x86_64" OR _hazel_qemu_arch STREQUAL "amd64")
        list(APPEND _hazel_flags -M q35,smm=off)
    elseif(_hazel_qemu_arch STREQUAL "aarch64" OR _hazel_qemu_arch STREQUAL "arm64")
        list(APPEND _hazel_flags -M virt)
    elseif(_hazel_qemu_arch STREQUAL "riscv64")
        list(APPEND _hazel_flags -M virt)
    endif()

    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(_hazel_qemu_default_common_flags out_var architecture)
    set(_hazel_flags
        -m
        "${HAZEL_QEMU_MEMORY}"
        -no-reboot
        -no-shutdown
        -serial
        "${HAZEL_QEMU_SERIAL}"
        -rtc
        "base=${HAZEL_QEMU_RTC_BASE}"
        -boot
        "order=d,menu=on,splash-time=0"
        -smp
        "${HAZEL_QEMU_SMP}"
    )

    _hazel_qemu_arch_machine_flags(_hazel_machine_flags "${architecture}")
    list(APPEND _hazel_flags ${_hazel_machine_flags})

    set(_hazel_qemu_vnc_var "${PROJECT_NAME}_QEMU_VNC")
    if(DEFINED ${_hazel_qemu_vnc_var})
        if(${${_hazel_qemu_vnc_var}})
            list(APPEND _hazel_flags -vnc 127.0.0.1:1)
        endif()
    endif()

    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(_hazel_qemu_default_accel_flags out_var architecture)
    string(TOLOWER "${architecture}" _hazel_qemu_arch)
    set(_hazel_flags "")

    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        if(_hazel_qemu_arch STREQUAL "x86_64" OR _hazel_qemu_arch STREQUAL "amd64")
            set(_hazel_flags -enable-kvm -cpu max,+invtsc)
        else()
            set(_hazel_flags -enable-kvm)
        endif()
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        set(_hazel_flags -accel hvf -cpu host)
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(_hazel_flags -accel whpx)
    endif()

    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(_hazel_qemu_default_debug_flags out_var log_file)
    set(_hazel_flags
        -d
        int
        -D
        "${log_file}"
        -S
        -s
    )
    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(_hazel_qemu_default_firmware_flags out_var architecture)
    string(TOLOWER "${architecture}" _hazel_qemu_arch)
    set(_hazel_flags "")

    if(_hazel_qemu_arch STREQUAL "x86_64" OR _hazel_qemu_arch STREQUAL "amd64")
        if(
            DEFINED OVMF_CODE_BINARY_PATH
            AND DEFINED OVMF_VARS_BINARY_PATH
            AND NOT OVMF_CODE_BINARY_PATH STREQUAL ""
            AND NOT OVMF_VARS_BINARY_PATH STREQUAL ""
        )
            if(EXISTS "${OVMF_CODE_BINARY_PATH}" AND EXISTS "${OVMF_VARS_BINARY_PATH}")
                list(
                    APPEND _hazel_flags
                    -drive
                    "if=pflash,format=raw,unit=0,file=${OVMF_CODE_BINARY_PATH},readonly=on"
                    -drive
                    "if=pflash,format=raw,unit=1,file=${OVMF_VARS_BINARY_PATH}"
                )
            else()
                message(
                    WARNING
                    "OVMF paths are configured but files are missing; QEMU will run without pflash firmware."
                )
            endif()
        endif()
    endif()

    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(add_qemu_targets)
    set(oneValueArgs
        ISO_FILE
        ARCHITECTURE
        RUN_TARGET
        DEBUG_TARGET
        LOG_FILE
    )
    set(multiValueArgs COMMON_FLAGS ACCEL_FLAGS DEBUG_FLAGS FIRMWARE_FLAGS)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_ISO_FILE)
        message(FATAL_ERROR "add_qemu_targets: ISO_FILE argument is required.")
    endif()

    if(NOT ARG_ARCHITECTURE)
        if(DEFINED ${PROJECT_NAME}_ARCHITECTURE)
            set(_hazel_qemu_architecture "${${PROJECT_NAME}_ARCHITECTURE}")
        else()
            set(_hazel_qemu_architecture "${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    else()
        set(_hazel_qemu_architecture "${ARG_ARCHITECTURE}")
    endif()

    _hazel_qemu_binary_candidates(_hazel_qemu_candidates "${_hazel_qemu_architecture}")
    find_program(_hazel_qemu_cmd NAMES ${_hazel_qemu_candidates})
    if(NOT _hazel_qemu_cmd)
        message(
            STATUS
            "QEMU executable for architecture '${_hazel_qemu_architecture}' not found; run/debug targets not generated."
        )
        return()
    endif()

    if(NOT ARG_RUN_TARGET)
        set(_hazel_run_target "run")
    else()
        set(_hazel_run_target "${ARG_RUN_TARGET}")
    endif()

    if(NOT ARG_DEBUG_TARGET)
        set(_hazel_debug_target "debug")
    else()
        set(_hazel_debug_target "${ARG_DEBUG_TARGET}")
    endif()

    if(TARGET ${_hazel_run_target})
        message(FATAL_ERROR "add_qemu_targets: target '${_hazel_run_target}' already exists.")
    endif()
    if(TARGET ${_hazel_debug_target})
        message(FATAL_ERROR "add_qemu_targets: target '${_hazel_debug_target}' already exists.")
    endif()

    if(NOT ARG_LOG_FILE)
        set(_hazel_log_file "${CMAKE_BINARY_DIR}/qemu-logs.txt")
    else()
        set(_hazel_log_file "${ARG_LOG_FILE}")
    endif()

    if(ARG_COMMON_FLAGS)
        set(_hazel_common_flags "${ARG_COMMON_FLAGS}")
    else()
        _hazel_qemu_default_common_flags(_hazel_common_flags "${_hazel_qemu_architecture}")
    endif()

    if(ARG_ACCEL_FLAGS)
        set(_hazel_accel_flags "${ARG_ACCEL_FLAGS}")
    else()
        _hazel_qemu_default_accel_flags(_hazel_accel_flags "${_hazel_qemu_architecture}")
    endif()

    if(ARG_DEBUG_FLAGS)
        set(_hazel_debug_flags "${ARG_DEBUG_FLAGS}")
    else()
        _hazel_qemu_default_debug_flags(_hazel_debug_flags "${_hazel_log_file}")
    endif()

    if(ARG_FIRMWARE_FLAGS)
        set(_hazel_firmware_flags "${ARG_FIRMWARE_FLAGS}")
    else()
        _hazel_qemu_default_firmware_flags(_hazel_firmware_flags "${_hazel_qemu_architecture}")
    endif()

    add_custom_target(
        ${_hazel_run_target}
        COMMAND
            "${_hazel_qemu_cmd}" -cdrom "${ARG_ISO_FILE}" ${_hazel_firmware_flags}
            ${_hazel_common_flags} ${_hazel_accel_flags}
        DEPENDS "${ARG_ISO_FILE}"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "Launching QEMU (accelerated, arch=${_hazel_qemu_architecture})"
        USES_TERMINAL
    )

    add_custom_target(
        ${_hazel_debug_target}
        COMMAND
            "${_hazel_qemu_cmd}" -cdrom "${ARG_ISO_FILE}" ${_hazel_firmware_flags}
            ${_hazel_common_flags} ${_hazel_debug_flags}
        DEPENDS "${ARG_ISO_FILE}"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "Launching QEMU (debug mode, arch=${_hazel_qemu_architecture})"
        USES_TERMINAL
    )
endfunction()
