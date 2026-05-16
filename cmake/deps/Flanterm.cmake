include_guard()

set(HAZEL_DEP_FLANTERM_REPOSITORY
    "https://github.com/Mintsuki/Flanterm.git"
    CACHE STRING
    "Flanterm repository URL"
)
set(HAZEL_DEP_FLANTERM_TAG "trunk" CACHE STRING "Flanterm git tag")

function(setup_flanterm)
    hazel_cpm_add_package(
        NAME
        flanterm
        GIT_REPOSITORY
        "${HAZEL_DEP_FLANTERM_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_FLANTERM_TAG}"
        DOWNLOAD_ONLY
        YES
    )

    set(_hazel_flanterm_source_dir "")
    if(DEFINED flanterm_SOURCE_DIR AND NOT "${flanterm_SOURCE_DIR}" STREQUAL "")
        set(_hazel_flanterm_source_dir "${flanterm_SOURCE_DIR}")
    elseif(
        DEFINED CPM_PACKAGE_flanterm_SOURCE_DIR
        AND NOT "${CPM_PACKAGE_flanterm_SOURCE_DIR}" STREQUAL ""
    )
        set(_hazel_flanterm_source_dir "${CPM_PACKAGE_flanterm_SOURCE_DIR}")
    endif()

    if("${_hazel_flanterm_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "flanterm was fetched, but CPM did not provide a source directory variable."
        )
    endif()

    set(_hazel_flanterm_src_dir "${_hazel_flanterm_source_dir}/src")

    if(NOT DEFINED FLANTERM_SOURCES)
        if(NOT EXISTS "${_hazel_flanterm_src_dir}")
            message(
                FATAL_ERROR
                "flanterm was fetched but '${_hazel_flanterm_src_dir}' is missing."
            )
        endif()

        file(
            GLOB_RECURSE _hazel_flanterm_sources
            CONFIGURE_DEPENDS
            "${_hazel_flanterm_src_dir}/*.c"
        )

        file(
            GLOB_RECURSE _hazel_flanterm_headers
            CONFIGURE_DEPENDS
            "${_hazel_flanterm_src_dir}/*.h"
        )

        set(FLANTERM_SOURCES "${_hazel_flanterm_sources}")
        set(FLANTERM_HEADERS "${_hazel_flanterm_headers}")
        set(FLANTERM_INCLUDES "${_hazel_flanterm_src_dir}")
    endif()

    if(NOT DEFINED FLANTERM_INCLUDES)
        if(EXISTS "${_hazel_flanterm_src_dir}")
            set(FLANTERM_INCLUDES "${_hazel_flanterm_src_dir}")
        else()
            set(FLANTERM_INCLUDES "${_hazel_flanterm_source_dir}")
        endif()
    endif()

    set(flanterm_SOURCE_DIR "${_hazel_flanterm_source_dir}" PARENT_SCOPE)
    set(FLANTERM_ROOT_DIR "${_hazel_flanterm_source_dir}" PARENT_SCOPE)
    if(DEFINED FLANTERM_SOURCES)
        set(FLANTERM_SOURCES "${FLANTERM_SOURCES}" PARENT_SCOPE)
    endif()
    if(DEFINED FLANTERM_HEADERS)
        set(FLANTERM_HEADERS "${FLANTERM_HEADERS}" PARENT_SCOPE)
    endif()
    if(DEFINED FLANTERM_INCLUDES)
        set(FLANTERM_INCLUDES "${FLANTERM_INCLUDES}" PARENT_SCOPE)
    endif()
endfunction()
