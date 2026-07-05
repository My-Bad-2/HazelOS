include_guard(GLOBAL)

set(HAZEL_CPM_DOWNLOAD_VERSION "0.42.3")
set(HAZEL_CPM_HASH_SUM "a609e875fd532b067174250f6abbc3dac22fe2d64869783fb1e80bda1625c844")

set(HAZEL_CPM_SOURCE_CACHE
    "${CMAKE_SOURCE_DIR}/cache"
    CACHE PATH
    "Global source cache used by CPM.cmake"
)

if(NOT DEFINED CPM_SOURCE_CACHE OR "${CPM_SOURCE_CACHE}" STREQUAL "")
    set(CPM_SOURCE_CACHE
        "${HAZEL_CPM_SOURCE_CACHE}"
        CACHE PATH
        "Directory used by CPM.cmake to cache package sources"
        FORCE
    )
endif()

if(CPM_SOURCE_CACHE)
    set(CPM_DOWNLOAD_LOCATION "${CPM_SOURCE_CACHE}/cpm/CPM_${HAZEL_CPM_DOWNLOAD_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE} AND NOT "$ENV{CPM_SOURCE_CACHE}" STREQUAL "")
    set(CPM_DOWNLOAD_LOCATION "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${HAZEL_CPM_DOWNLOAD_VERSION}.cmake")
else()
    set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${HAZEL_CPM_DOWNLOAD_VERSION}.cmake")
endif()

get_filename_component(CPM_DOWNLOAD_LOCATION "${CPM_DOWNLOAD_LOCATION}" ABSOLUTE)
get_filename_component(_hazel_cpm_download_dir "${CPM_DOWNLOAD_LOCATION}" DIRECTORY)
file(MAKE_DIRECTORY "${_hazel_cpm_download_dir}")

if(NOT EXISTS "${CPM_DOWNLOAD_LOCATION}")
    message(STATUS "Downloading CPM.cmake v${HAZEL_CPM_DOWNLOAD_VERSION}...")

    file(
        DOWNLOAD
            "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${HAZEL_CPM_DOWNLOAD_VERSION}/CPM.cmake"
        "${CPM_DOWNLOAD_LOCATION}"
        EXPECTED_HASH SHA256=${HAZEL_CPM_HASH_SUM}
        TLS_VERIFY ON
        STATUS _hazel_cpm_download_status
        LOG _hazel_cpm_download_log
    )

    list(GET _hazel_cpm_download_status 0 _hazel_cpm_download_code)
    list(GET _hazel_cpm_download_status 1 _hazel_cpm_download_message)
    if(NOT _hazel_cpm_download_code EQUAL 0)
        file(REMOVE "${CPM_DOWNLOAD_LOCATION}")
        message(
            FATAL_ERROR
            "Failed to download CPM.cmake: ${_hazel_cpm_download_message}\n${_hazel_cpm_download_log}"
        )
    endif()
endif()

include("${CPM_DOWNLOAD_LOCATION}")

function(hazel_cpm_add_package)
    if(NOT COMMAND CPMAddPackage)
        message(
            FATAL_ERROR
            "CPMAddPackage is unavailable. Ensure cmake/deps/CPM.cmake is included first."
        )
    endif()

    cpmaddpackage(${ARGN})
endfunction()
