include_guard()

set(HAZEL_DEP_FREESTND_HDRS_REPOSITORY
    "https://codeberg.org/OSDev/freestnd-cxx-hdrs.git"
    CACHE STRING
    "freestnd-cxx-hdrs repository URL"
)
set(HAZEL_DEP_FREESTND_HDRS_TAG "trunk" CACHE STRING "freestnd-cxx-hdrs git tag")

function(setup_freestnd_cxx_headers)
    hazel_cpm_add_package(
        NAME
        freestnd_hdrs
        GIT_REPOSITORY
        "${HAZEL_DEP_FREESTND_HDRS_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_FREESTND_HDRS_TAG}"
        DOWNLOAD_ONLY
        YES
    )

    set(_hazel_freestnd_source_dir "")
    if(DEFINED freestnd_hdrs_SOURCE_DIR AND NOT "${freestnd_hdrs_SOURCE_DIR}" STREQUAL "")
        set(_hazel_freestnd_source_dir "${freestnd_hdrs_SOURCE_DIR}")
    elseif(
        DEFINED CPM_PACKAGE_freestnd_hdrs_SOURCE_DIR
        AND NOT "${CPM_PACKAGE_freestnd_hdrs_SOURCE_DIR}" STREQUAL ""
    )
        set(_hazel_freestnd_source_dir "${CPM_PACKAGE_freestnd_hdrs_SOURCE_DIR}")
    endif()

    if("${_hazel_freestnd_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "freestnd-cxx-hdrs was fetched, but CPM did not provide a source directory variable."
        )
    endif()

    set(_hazel_freestnd_hdrs_dir
        "${_hazel_freestnd_source_dir}/${${PROJECT_NAME}_ARCHITECTURE}/include"
    )
    if(NOT EXISTS "${_hazel_freestnd_hdrs_dir}")
        message(
            FATAL_ERROR
            "freestnd headers directory '${_hazel_freestnd_hdrs_dir}' was not found."
        )
    endif()

    set(FREESTND_HDRS_DIR
        "${_hazel_freestnd_hdrs_dir}"
        CACHE PATH
        "Freestanding C++ headers include directory"
        FORCE
    )
    set(FREESTND_HDRS_DIR "${_hazel_freestnd_hdrs_dir}" PARENT_SCOPE)
endfunction()
