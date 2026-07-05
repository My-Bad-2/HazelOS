include_guard()

set(HAZEL_DEP_LIMINE_RELEASE_BASE_URL
    "https://github.com/limine-bootloader/limine/releases/download"
    CACHE STRING
    "Limine release base URL"
)
set(HAZEL_DEP_LIMINE_TAG "v12.3.3" CACHE STRING "Limine release tag")
set(HAZEL_DEP_LIMINE_ASSET
    ""
    CACHE STRING
    "Limine release asset name (zip/tar). Leave empty to auto-detect."
)
set(HAZEL_DEP_LIMINE_CACHE_DIR
    "${CMAKE_SOURCE_DIR}/cache/limine"
    CACHE PATH
    "Directory to store Limine release assets"
)
set(HAZEL_DEP_LIMINE_SOURCE_DIR
    ""
    CACHE PATH
    "Override Limine source directory"
)
set(HAZEL_DEP_LIMINE_TOOL_PATH
    ""
    CACHE FILEPATH
    "Override Limine deploy tool path"
)

function(_hazel_limine_require_file file_path)
    if(NOT EXISTS "${file_path}")
        message(FATAL_ERROR "Missing required Limine artifact: ${file_path}")
    endif()
endfunction()

function(_hazel_limine_download_release_asset out_asset out_path base_url tag dest_dir)
    foreach(_hazel_asset IN LISTS ARGN)
        if("${_hazel_asset}" STREQUAL "")
            continue()
        endif()

        set(_hazel_dest "${dest_dir}/${_hazel_asset}")
        if(EXISTS "${_hazel_dest}")
            set(${out_asset} "${_hazel_asset}" PARENT_SCOPE)
            set(${out_path} "${_hazel_dest}" PARENT_SCOPE)
            return()
        endif()

        set(_hazel_url "${base_url}/${tag}/${_hazel_asset}")
        message(STATUS "Downloading Limine release asset ${_hazel_asset}...")
        file(
            DOWNLOAD "${_hazel_url}"
            "${_hazel_dest}.tmp"
            TLS_VERIFY ON
            TIMEOUT 120
            STATUS _hazel_download_status
            LOG _hazel_download_log
        )

        list(GET _hazel_download_status 0 _hazel_status_code)
        if(_hazel_status_code EQUAL 0)
            file(RENAME "${_hazel_dest}.tmp" "${_hazel_dest}")
            message(STATUS "Downloaded ${_hazel_asset} to: ${_hazel_dest}")
            set(${out_asset} "${_hazel_asset}" PARENT_SCOPE)
            set(${out_path} "${_hazel_dest}" PARENT_SCOPE)
            return()
        endif()

        file(REMOVE "${_hazel_dest}.tmp")
    endforeach()

    message(
        FATAL_ERROR
        "Failed to download Limine release assets from ${base_url}/${tag}. Check HAZEL_DEP_LIMINE_ASSET and HAZEL_DEP_LIMINE_TAG (expected limine-binary.*)."
    )
endfunction()

function(setup_limine)
    set(_hazel_needs_bios OFF)
    if("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "x86_64")
        set(_hazel_limine_efi_file "BOOTX64.EFI")
        set(_hazel_needs_bios ON)
    elseif("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "aarch64")
        set(_hazel_limine_efi_file "BOOTAA64.EFI")
    else()
        message(FATAL_ERROR "Unsupported Limine architecture '${${PROJECT_NAME}_ARCHITECTURE}'.")
    endif()

    set(_hazel_limine_source_dir "${HAZEL_DEP_LIMINE_SOURCE_DIR}")
    if("${_hazel_limine_source_dir}" STREQUAL "")
        set(_hazel_limine_cache_dir "${HAZEL_DEP_LIMINE_CACHE_DIR}")
        file(MAKE_DIRECTORY "${_hazel_limine_cache_dir}")

        set(_hazel_limine_asset_candidates "")
        if(NOT "${HAZEL_DEP_LIMINE_ASSET}" STREQUAL "")
            list(APPEND _hazel_limine_asset_candidates "${HAZEL_DEP_LIMINE_ASSET}")
        else()
            set(_hazel_limine_tag "${HAZEL_DEP_LIMINE_TAG}")
            list(
                APPEND _hazel_limine_asset_candidates
                "limine-binary.tar.xz"
                "limine-binary.tar.gz"
                "limine-binary.zip"
            )
            if(_hazel_limine_tag MATCHES "-binary$")
                list(
                    APPEND _hazel_limine_asset_candidates
                    "limine-${_hazel_limine_tag}.tar.xz"
                    "limine-${_hazel_limine_tag}.zip"
                    "limine-${_hazel_limine_tag}.tar.gz"
                )
            else()
                list(
                    APPEND _hazel_limine_asset_candidates
                    "limine-${_hazel_limine_tag}-binary.tar.xz"
                    "limine-${_hazel_limine_tag}-binary.zip"
                    "limine-${_hazel_limine_tag}-binary.tar.gz"
                )
            endif()
        endif()

        _hazel_limine_download_release_asset(
            _hazel_limine_asset
            _hazel_limine_archive
            "${HAZEL_DEP_LIMINE_RELEASE_BASE_URL}"
            "${HAZEL_DEP_LIMINE_TAG}"
            "${_hazel_limine_cache_dir}"
            ${_hazel_limine_asset_candidates}
        )

        set(_hazel_extract_stamp
            "${_hazel_limine_cache_dir}/.limine-extracted-${HAZEL_DEP_LIMINE_TAG}"
        )
        if(NOT EXISTS "${_hazel_extract_stamp}")
            execute_process(
                COMMAND "${CMAKE_COMMAND}" -E tar xf "${_hazel_limine_archive}"
                WORKING_DIRECTORY "${_hazel_limine_cache_dir}"
                RESULT_VARIABLE _hazel_extract_result
            )
            if(NOT _hazel_extract_result EQUAL 0)
                message(
                    FATAL_ERROR
                    "Failed to extract Limine release asset '${_hazel_limine_archive}'."
                )
            endif()
            file(WRITE "${_hazel_extract_stamp}" "ok")
        endif()

        if(EXISTS "${_hazel_limine_cache_dir}/limine-uefi-cd.bin")
            set(_hazel_limine_source_dir "${_hazel_limine_cache_dir}")
        else()
            file(GLOB _hazel_limine_dir_candidates LIST_DIRECTORIES true "${_hazel_limine_cache_dir}/*")
            foreach(_hazel_candidate IN LISTS _hazel_limine_dir_candidates)
                if(IS_DIRECTORY "${_hazel_candidate}" AND EXISTS "${_hazel_candidate}/limine-uefi-cd.bin")
                    set(_hazel_limine_source_dir "${_hazel_candidate}")
                    break()
                endif()
            endforeach()
        endif()
    endif()

    if("${_hazel_limine_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "Limine assets are unavailable. Set HAZEL_DEP_LIMINE_SOURCE_DIR to a directory with Limine binaries."
        )
    endif()

    set(_hazel_limine_tool_source "${_hazel_limine_source_dir}/limine.c")
    set(_hazel_limine_tool_binary "")
    if(NOT "${HAZEL_DEP_LIMINE_TOOL_PATH}" STREQUAL "")
        set(_hazel_limine_tool_binary "${HAZEL_DEP_LIMINE_TOOL_PATH}")
    elseif(EXISTS "${_hazel_limine_source_dir}/limine")
        set(_hazel_limine_tool_binary "${_hazel_limine_source_dir}/limine")
    elseif(EXISTS "${_hazel_limine_source_dir}/limine-deploy")
        set(_hazel_limine_tool_binary "${_hazel_limine_source_dir}/limine-deploy")
    endif()
    set(_hazel_limine_iso_dir "${${PROJECT_NAME}_ISO_DIR}")

    if(_hazel_needs_bios)
        _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-bios.sys")
        _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-bios-cd.bin")
    endif()
    _hazel_limine_require_file("${_hazel_limine_source_dir}/limine-uefi-cd.bin")
    _hazel_limine_require_file("${_hazel_limine_source_dir}/${_hazel_limine_efi_file}")

    if(EXISTS "${_hazel_limine_tool_source}")
        find_program(_hazel_limine_host_cc NAMES cc clang gcc)
        if(NOT _hazel_limine_host_cc)
            message(
                FATAL_ERROR
                "A host C compiler (cc/clang/gcc) is required to build the Limine helper tool."
            )
        endif()

        set(_hazel_limine_tool_binary "${_hazel_limine_source_dir}/limine")
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
    elseif(NOT "${_hazel_limine_tool_binary}" STREQUAL "")
        add_custom_target(build_limine_tool DEPENDS "${_hazel_limine_tool_binary}")
    elseif(_hazel_needs_bios)
        message(
            FATAL_ERROR
            "Limine deploy tool not found. Set HAZEL_DEP_LIMINE_TOOL_PATH or include limine.c in the release asset."
        )
    else()
        add_custom_target(build_limine_tool)
    endif()

    set(_hazel_limine_install_commands
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_hazel_limine_iso_dir}/boot/limine"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_hazel_limine_iso_dir}/EFI/BOOT"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different "${_hazel_limine_source_dir}/limine-uefi-cd.bin"
            "${_hazel_limine_iso_dir}/boot/limine/limine-uefi-cd.bin"
        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
            "${_hazel_limine_source_dir}/${_hazel_limine_efi_file}"
            "${_hazel_limine_iso_dir}/EFI/BOOT/${_hazel_limine_efi_file}"
    )

    if(_hazel_needs_bios)
        list(
            APPEND _hazel_limine_install_commands
            COMMAND
                "${CMAKE_COMMAND}" -E copy_if_different "${_hazel_limine_source_dir}/limine-bios.sys"
                "${_hazel_limine_iso_dir}/boot/limine/limine-bios.sys"
            COMMAND
                "${CMAKE_COMMAND}" -E copy_if_different
                "${_hazel_limine_source_dir}/limine-bios-cd.bin"
                "${_hazel_limine_iso_dir}/boot/limine/limine-bios-cd.bin"
        )
    endif()

    add_custom_target(
        install_limine
        DEPENDS build_limine_tool
        ${_hazel_limine_install_commands}
        COMMENT "Installing Limine binaries into ${_hazel_limine_iso_dir}"
        VERBATIM
    )

    if(_hazel_needs_bios)
        add_custom_target(
            patch_limine
            DEPENDS install_limine "${${PROJECT_NAME}_ISO_FILE}"
            COMMAND "${_hazel_limine_tool_binary}" bios-install "${${PROJECT_NAME}_ISO_FILE}"
            COMMENT "Patching ${${PROJECT_NAME}_ISO_FILE} with Limine BIOS bootloader"
            VERBATIM
        )
    else()
        message(STATUS "Limine BIOS patch disabled for arch '${${PROJECT_NAME}_ARCHITECTURE}'.")
        add_custom_target(patch_limine DEPENDS install_limine)
    endif()
endfunction()
