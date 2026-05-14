include_guard()

include(CMakeParseArguments)

set(HAZEL_ISO_BIOS_BOOT_IMAGE
    ""
    CACHE STRING
    "Path inside the ISO staging directory for BIOS El Torito boot image. Empty disables BIOS boot."
)
set(HAZEL_ISO_EFI_BOOT_IMAGE
    ""
    CACHE STRING
    "Path inside the ISO staging directory for EFI boot image. Empty disables EFI boot."
)
option(HAZEL_ISO_ENABLE_HFSPLUS "Enable HFS+/APM metadata for hybrid EFI images." ON)

function(_hazel_iso_build_default_flags out_var staging_dir architecture)
    set(_hazel_flags
        -as
        mkisofs
        -R
        -r
        -J
    )

    set(_hazel_bios_boot_image "${HAZEL_ISO_BIOS_BOOT_IMAGE}")
    set(_hazel_efi_boot_image "${HAZEL_ISO_EFI_BOOT_IMAGE}")

    if(_hazel_bios_boot_image STREQUAL "" AND _hazel_efi_boot_image STREQUAL "")
        if(architecture STREQUAL "x86_64")
            set(_hazel_bios_boot_image "boot/limine/limine-bios-cd.bin")
            set(_hazel_efi_boot_image "boot/limine/limine-uefi-cd.bin")
        else()
            set(_hazel_efi_boot_image "boot/limine/limine-uefi-cd.bin")
        endif()
    endif()

    if(NOT _hazel_bios_boot_image STREQUAL "")
        list(
            APPEND _hazel_flags
            -b
            "${_hazel_bios_boot_image}"
            -no-emul-boot
            -boot-load-size
            4
            -boot-info-table
        )
    endif()

    if(NOT _hazel_efi_boot_image STREQUAL "")
        if(HAZEL_ISO_ENABLE_HFSPLUS)
            list(APPEND _hazel_flags -hfsplus -apm-block-size 2048)
        endif()

        list(
            APPEND _hazel_flags
            --efi-boot
            "${_hazel_efi_boot_image}"
            -efi-boot-part
            --efi-boot-image
            --protective-msdos-label
        )
    endif()

    if(_hazel_bios_boot_image STREQUAL "" AND _hazel_efi_boot_image STREQUAL "")
        message(
            WARNING
            "build_iso: no BIOS or EFI boot image is configured; resulting ISO may be non-bootable."
        )
    endif()

    set(${out_var} "${_hazel_flags}" PARENT_SCOPE)
endfunction()

function(build_iso)
    set(oneValueArgs STAGING_DIR TRIGGER_NAME OUTPUT_FILE ARCHITECTURE)
    set(multiValueArgs XORRISO_FLAGS DEPENDS)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_STAGING_DIR)
        message(FATAL_ERROR "build_iso: STAGING_DIR argument is required.")
    endif()

    if(NOT ARG_TRIGGER_NAME)
        message(FATAL_ERROR "build_iso: TRIGGER_NAME argument is required.")
    endif()

    if(NOT ARG_OUTPUT_FILE)
        set(_hazel_iso_output "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.iso")
    else()
        set(_hazel_iso_output "${ARG_OUTPUT_FILE}")
    endif()

    if(NOT ARG_ARCHITECTURE)
        if(DEFINED ${PROJECT_NAME}_ARCHITECTURE)
            set(_hazel_iso_architecture "${${PROJECT_NAME}_ARCHITECTURE}")
        else()
            set(_hazel_iso_architecture "${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    else()
        set(_hazel_iso_architecture "${ARG_ARCHITECTURE}")
    endif()

    find_program(_hazel_xorriso_cmd xorriso)
    if(NOT _hazel_xorriso_cmd)
        message(FATAL_ERROR "xorriso was not found in PATH.")
    endif()

    if(ARG_XORRISO_FLAGS)
        set(_hazel_xorriso_flags "${ARG_XORRISO_FLAGS}")
    else()
        _hazel_iso_build_default_flags(
            _hazel_xorriso_flags
            "${ARG_STAGING_DIR}"
            "${_hazel_iso_architecture}"
        )
    endif()

    add_custom_command(
        OUTPUT "${_hazel_iso_output}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${ARG_STAGING_DIR}"
        COMMAND
            "${_hazel_xorriso_cmd}" ${_hazel_xorriso_flags} "${ARG_STAGING_DIR}" -o
            "${_hazel_iso_output}"
        DEPENDS ${ARG_DEPENDS}
        COMMENT "Packing ${ARG_STAGING_DIR} into ${_hazel_iso_output}"
        VERBATIM
    )

    add_custom_target(${ARG_TRIGGER_NAME} DEPENDS "${_hazel_iso_output}")

    message(
        STATUS
        "Optional target '${ARG_TRIGGER_NAME}' registered for ${_hazel_iso_output} (arch='${_hazel_iso_architecture}')."
    )
endfunction()
