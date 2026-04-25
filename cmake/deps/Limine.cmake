include_guard()

set(HAZEL_DEP_LIMINE_REPOSITORY
    "https://github.com/limine-bootloader/limine.git"
    CACHE STRING
    "Limine repository URL"
)
set(HAZEL_DEP_LIMINE_TAG "v11.4.1-binary" CACHE STRING "Limine git tag")

function(_hazel_limine_require_file file_path)
    if(NOT EXISTS "${file_path}")
        message(FATAL_ERROR "Missing required Limine artifact: ${file_path}")
    endif()
endfunction()

function(setup_limine)
    if("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "x86_64")
        set(_hazel_limine_efi_file "BOOTX64.EFI")
    else()
        message(FATAL_ERROR "Unsupported Limine architecture '${${PROJECT_NAME}_ARCHITECTURE}'.")
    endif()

    hazel_cpm_add_package(
        NAME
        limine_artifacts
        GIT_REPOSITORY
        "${HAZEL_DEP_LIMINE_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_LIMINE_TAG}"
        DOWNLOAD_ONLY
        YES
    )

    set(_hazel_limine_source_dir "")
    if(DEFINED limine_artifacts_SOURCE_DIR AND NOT "${limine_artifacts_SOURCE_DIR}" STREQUAL "")
        set(_hazel_limine_source_dir "${limine_artifacts_SOURCE_DIR}")
    elseif(
        DEFINED CPM_PACKAGE_limine_artifacts_SOURCE_DIR
        AND NOT "${CPM_PACKAGE_limine_artifacts_SOURCE_DIR}" STREQUAL ""
    )
        set(_hazel_limine_source_dir "${CPM_PACKAGE_limine_artifacts_SOURCE_DIR}")
    endif()

    if("${_hazel_limine_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "Limine artifacts were fetched, but CPM did not provide a source directory variable."
        )
    endif()

    set(_hazel_limine_tool_source "${_hazel_limine_source_dir}/limine.c")
    set(_hazel_limine_tool_binary "${_hazel_limine_source_dir}/limine")
    set(_hazel_limine_iso_dir "${${PROJECT_NAME}_ISO_DIR}")

    _hazel_limine_require_file("${_hazel_limine_tool_source}")
    _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-bios.sys")
    _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-bios-cd.bin")
    _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-uefi-cd.bin")
    _hazel_limine_require_file("${_hazel_limine_source_dir}/${_hazel_limine_efi_file}")

    find_program(_hazel_limine_host_cc NAMES cc clang gcc)
    if(NOT _hazel_limine_host_cc)
        message(
            FATAL_ERROR
            "A host C compiler (cc/clang/gcc) is required to build the Limine helper tool."
        )
    endif()

    add_custom_command(
        OUTPUT "${_hazel_limine_tool_binary}"
        COMMAND
            "${_hazel_limine_host_cc}" -std=c99 -O2 -pipe "${_hazel_limine_tool_source}" -o
            "${_hazel_limine_tool_binary}"
        DEPENDS "${_hazel_limine_tool_source}"
        COMMENT "Compiling Limine host deploy tool"
        VERBATIM
    )

    add_custom_target(build_limine_tool DEPENDS "${_hazel_limine_tool_binary}")

    add_custom_target(
        install_limine
        DEPENDS build_limine_tool
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_hazel_limine_iso_dir}/boot/limine"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_hazel_limine_iso_dir}/EFI/BOOT"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different "${_hazel_limine_source_dir}/limine-bios.sys"
            "${_hazel_limine_iso_dir}/boot/limine/limine-bios.sys"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different "${_hazel_limine_source_dir}/limine-bios-cd.bin"
            "${_hazel_limine_iso_dir}/boot/limine/limine-bios-cd.bin"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different "${_hazel_limine_source_dir}/limine-uefi-cd.bin"
            "${_hazel_limine_iso_dir}/boot/limine/limine-uefi-cd.bin"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
            "${_hazel_limine_source_dir}/${_hazel_limine_efi_file}"
            "${_hazel_limine_iso_dir}/EFI/BOOT/${_hazel_limine_efi_file}"
        COMMENT "Installing Limine binaries into ${_hazel_limine_iso_dir}"
        VERBATIM
    )

    add_custom_target(
        patch_limine
        DEPENDS install_limine "${${PROJECT_NAME}_ISO_FILE}"
        COMMAND "${_hazel_limine_tool_binary}" bios-install "${${PROJECT_NAME}_ISO_FILE}"
        COMMENT "Patching ${${PROJECT_NAME}_ISO_FILE} with Limine BIOS bootloader"
        VERBATIM
    )
endfunction()
