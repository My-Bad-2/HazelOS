include_guard()

set(OVMF_INSTALL_DIR "${CMAKE_SOURCE_DIR}/cache/ovmf" CACHE PATH "Directory to store OVMF binaries")
set(HAZEL_OVMF_BASE_URL
    "https://raw.githubusercontent.com/retrage/edk2-nightly/fe4d3c4885d31acbaeb874ee5d153256aeafb393/bin"
    CACHE STRING
    "Base URL for downloading OVMF binaries"
)

function(_hazel_download_file_if_missing remote_url local_path label)
    if(EXISTS "${local_path}")
        message(STATUS "${label} already exists at: ${local_path}")
        return()
    endif()

    message(STATUS "Downloading ${label}...")
    file(
        DOWNLOAD "${remote_url}"
        "${local_path}"
        TLS_VERIFY ON
        TIMEOUT 120
        STATUS _hazel_download_status
        LOG _hazel_download_log
    )

    list(GET _hazel_download_status 0 _hazel_status_code)
    list(GET _hazel_download_status 1 _hazel_status_message)
    if(NOT _hazel_status_code EQUAL 0)
        file(REMOVE "${local_path}")
        message(
            FATAL_ERROR
            "Failed to download ${label}: ${_hazel_status_message}\n${_hazel_download_log}"
        )
    endif()

    message(STATUS "Downloaded ${label} to: ${local_path}")
endfunction()

function(setup_ovmf)
    if("${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "x86_64")
        set(_hazel_ovmf_filename_code "RELEASEX64_OVMF_CODE.fd")
        set(_hazel_ovmf_filename_vars "RELEASEX64_OVMF_VARS.fd")
    else()
        message(FATAL_ERROR "No OVMF mapping for architecture '${${PROJECT_NAME}_ARCHITECTURE}'.")
    endif()

    file(MAKE_DIRECTORY "${OVMF_INSTALL_DIR}")

    set(_hazel_ovmf_local_path_code "${OVMF_INSTALL_DIR}/${_hazel_ovmf_filename_code}")
    set(_hazel_ovmf_local_path_vars "${OVMF_INSTALL_DIR}/${_hazel_ovmf_filename_vars}")

    _hazel_download_file_if_missing(
        "${HAZEL_OVMF_BASE_URL}/${_hazel_ovmf_filename_code}"
        "${_hazel_ovmf_local_path_code}"
        "${_hazel_ovmf_filename_code}"
    )
    _hazel_download_file_if_missing(
        "${HAZEL_OVMF_BASE_URL}/${_hazel_ovmf_filename_vars}"
        "${_hazel_ovmf_local_path_vars}"
        "${_hazel_ovmf_filename_vars}"
    )

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
