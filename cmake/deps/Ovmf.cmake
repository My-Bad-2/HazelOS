include_guard()

set(OVMF_INSTALL_DIR "${CMAKE_SOURCE_DIR}/cache/ovmf" CACHE PATH "Directory to store OVMF binaries")
set(HAZEL_OVMF_BASE_URL
    "https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download"
    CACHE STRING
    "Base URL for downloading OVMF binaries"
)
set(HAZEL_OVMF_ASSET
    ""
    CACHE STRING
    "OVMF release asset name (tar.gz/tar.xz). Leave empty to auto-detect."
)
set(HAZEL_OVMF_CACHE_DIR
    "${CMAKE_SOURCE_DIR}/cache/ovmf"
    CACHE PATH
    "Directory to store OVMF release assets"
)
set(HAZEL_OVMF_EXTRACT_DIR
    "${CMAKE_SOURCE_DIR}/cache/ovmf/extracted"
    CACHE PATH
    "Directory to extract OVMF archives"
)
set(HAZEL_OVMF_SOURCE_DIR
    ""
    CACHE PATH
    "Override extracted OVMF directory"
)
set(HAZEL_OVMF_CODE_FILENAME
    ""
    CACHE STRING
    "Override OVMF code firmware filename inside the archive"
)
set(HAZEL_OVMF_VARS_FILENAME
    ""
    CACHE STRING
    "Override OVMF vars firmware filename inside the archive"
)

function(_hazel_ovmf_download_release_asset out_asset out_path base_url dest_dir)
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

        set(_hazel_url "${base_url}/${_hazel_asset}")
        message(STATUS "Downloading OVMF release asset ${_hazel_asset}...")
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
        "Failed to download OVMF release assets from ${base_url}. Check HAZEL_OVMF_ASSET."
    )
endfunction()

function(_hazel_find_ovmf_file out_var root_dir)
    foreach(_hazel_pattern IN LISTS ARGN)
        if("${_hazel_pattern}" STREQUAL "")
            continue()
        endif()

        file(GLOB_RECURSE _hazel_matches "${root_dir}/${_hazel_pattern}")
        list(LENGTH _hazel_matches _hazel_match_count)
        if(_hazel_match_count GREATER 0)
            list(GET _hazel_matches 0 _hazel_match)
            set(${out_var} "${_hazel_match}" PARENT_SCOPE)
            return()
        endif()
    endforeach()

    set(${out_var} "" PARENT_SCOPE)
endfunction()

function(setup_ovmf)
    if("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "x86_64")
        set(_hazel_ovmf_filename_code "ovmf-code-x86_64.fd")
        set(_hazel_ovmf_filename_vars "ovmf-vars-x86_64.fd")
    elseif("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "aarch64")
        set(_hazel_ovmf_filename_code "ovmf-code-aarch64.fd")
        set(_hazel_ovmf_filename_vars "ovmf-vars-aarch64.fd")
    else()
        message(FATAL_ERROR "No OVMF mapping for architecture '${${PROJECT_NAME}_ARCHITECTURE}'.")
    endif()

    file(MAKE_DIRECTORY "${OVMF_INSTALL_DIR}")

    set(_hazel_ovmf_source_dir "${HAZEL_OVMF_SOURCE_DIR}")
    if("${_hazel_ovmf_source_dir}" STREQUAL "")
        set(_hazel_ovmf_cache_dir "${HAZEL_OVMF_CACHE_DIR}")
        set(_hazel_ovmf_extract_dir "${HAZEL_OVMF_EXTRACT_DIR}")
        file(MAKE_DIRECTORY "${_hazel_ovmf_cache_dir}")
        file(MAKE_DIRECTORY "${_hazel_ovmf_extract_dir}")

        set(_hazel_ovmf_asset_candidates "")
        if(NOT "${HAZEL_OVMF_ASSET}" STREQUAL "")
            list(APPEND _hazel_ovmf_asset_candidates "${HAZEL_OVMF_ASSET}")
        else()
            list(
                APPEND _hazel_ovmf_asset_candidates
                "edk2-ovmf.tar.xz"
                "edk2-ovmf.tar.gz"
            )
        endif()

        _hazel_ovmf_download_release_asset(
            _hazel_ovmf_asset
            _hazel_ovmf_archive
            "${HAZEL_OVMF_BASE_URL}"
            "${_hazel_ovmf_cache_dir}"
            ${_hazel_ovmf_asset_candidates}
        )

        set(_hazel_extract_stamp "${_hazel_ovmf_extract_dir}/.ovmf-extracted-${_hazel_ovmf_asset}")
        if(NOT EXISTS "${_hazel_extract_stamp}")
            execute_process(
                COMMAND "${CMAKE_COMMAND}" -E tar xf "${_hazel_ovmf_archive}"
                WORKING_DIRECTORY "${_hazel_ovmf_extract_dir}"
                RESULT_VARIABLE _hazel_extract_result
            )
            if(NOT _hazel_extract_result EQUAL 0)
                message(
                    FATAL_ERROR
                    "Failed to extract OVMF release asset '${_hazel_ovmf_archive}'."
                )
            endif()
            file(WRITE "${_hazel_extract_stamp}" "ok")
        endif()

        set(_hazel_ovmf_source_dir "${_hazel_ovmf_extract_dir}")
    endif()

    if("${_hazel_ovmf_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "OVMF assets are unavailable. Set HAZEL_OVMF_SOURCE_DIR to the extracted OVMF archive."
        )
    endif()

    set(_hazel_ovmf_code_candidates "")
    set(_hazel_ovmf_vars_candidates "")
    if(NOT "${HAZEL_OVMF_CODE_FILENAME}" STREQUAL "")
        list(APPEND _hazel_ovmf_code_candidates "${HAZEL_OVMF_CODE_FILENAME}")
    endif()
    if(NOT "${HAZEL_OVMF_VARS_FILENAME}" STREQUAL "")
        list(APPEND _hazel_ovmf_vars_candidates "${HAZEL_OVMF_VARS_FILENAME}")
    endif()

    if(${PROJECT_NAME}_ARCHITECTURE STREQUAL "x86_64")
        if(_hazel_ovmf_code_candidates STREQUAL "")
            list(
                APPEND _hazel_ovmf_code_candidates
                "OVMF_CODE.fd"
                "OVMF_CODE_4M.fd"
                "RELEASEX64_OVMF_CODE.fd"
                "ovmf-code-x86_64.fd"
                "*X64*OVMF*CODE*.fd"
                "*OVMF_CODE*.fd"
            )
        endif()
        if(_hazel_ovmf_vars_candidates STREQUAL "")
            list(
                APPEND _hazel_ovmf_vars_candidates
                "OVMF_VARS.fd"
                "OVMF_VARS_4M.fd"
                "RELEASEX64_OVMF_VARS.fd"
                "ovmf-vars-x86_64.fd"
                "*X64*OVMF*VARS*.fd"
                "*OVMF_VARS*.fd"
            )
        endif()
    elseif(${PROJECT_NAME}_ARCHITECTURE STREQUAL "aarch64")
        if(_hazel_ovmf_code_candidates STREQUAL "")
            list(
                APPEND _hazel_ovmf_code_candidates
                "QEMU_EFI.fd"
                "RELEASEAARCH64_QEMU_EFI.fd"
                "ovmf-code-aarch64.fd"
                "*AARCH64*QEMU_EFI*.fd"
                "*QEMU_EFI*.fd"
            )
        endif()
        if(_hazel_ovmf_vars_candidates STREQUAL "")
            list(
                APPEND _hazel_ovmf_vars_candidates
                "QEMU_VARS.fd"
                "RELEASEAARCH64_QEMU_VARS.fd"
                "ovmf-vars-aarch64.fd"
                "*AARCH64*QEMU_VARS*.fd"
                "*QEMU_VARS*.fd"
            )
        endif()
    endif()

    _hazel_find_ovmf_file(
        _hazel_ovmf_code_source
        "${_hazel_ovmf_source_dir}"
        ${_hazel_ovmf_code_candidates}
    )
    _hazel_find_ovmf_file(
        _hazel_ovmf_vars_source
        "${_hazel_ovmf_source_dir}"
        ${_hazel_ovmf_vars_candidates}
    )

    if("${_hazel_ovmf_code_source}" STREQUAL "")
        message(
            FATAL_ERROR
            "OVMF code firmware was not found under '${_hazel_ovmf_source_dir}'. Set HAZEL_OVMF_CODE_FILENAME to the correct filename."
        )
    endif()
    if("${_hazel_ovmf_vars_source}" STREQUAL "")
        message(
            FATAL_ERROR
            "OVMF vars firmware was not found under '${_hazel_ovmf_source_dir}'. Set HAZEL_OVMF_VARS_FILENAME to the correct filename."
        )
    endif()

    set(_hazel_ovmf_local_path_code "${OVMF_INSTALL_DIR}/${_hazel_ovmf_filename_code}")
    set(_hazel_ovmf_local_path_vars "${OVMF_INSTALL_DIR}/${_hazel_ovmf_filename_vars}")

    file(COPY_FILE "${_hazel_ovmf_code_source}" "${_hazel_ovmf_local_path_code}" ONLY_IF_DIFFERENT)
    file(COPY_FILE "${_hazel_ovmf_vars_source}" "${_hazel_ovmf_local_path_vars}" ONLY_IF_DIFFERENT)

    set(OVMF_CODE_BINARY_PATH
        "${_hazel_ovmf_local_path_code}"
        CACHE FILEPATH
        "Path to the downloaded OVMF (Code) binary"
        FORCE
    )
    set(OVMF_VARS_BINARY_PATH
        "${_hazel_ovmf_local_path_vars}"
        CACHE FILEPATH
        "Path to the downloaded OVMF (Vars) binary"
        FORCE
    )
    set(OVMF_CODE_BINARY_PATH "${_hazel_ovmf_local_path_code}" PARENT_SCOPE)
    set(OVMF_VARS_BINARY_PATH "${_hazel_ovmf_local_path_vars}" PARENT_SCOPE)
endfunction()
