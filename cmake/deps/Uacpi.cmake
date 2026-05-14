include_guard()

set(HAZEL_DEP_UACPI_REPOSITORY
    "https://github.com/uACPI/uACPI.git"
    CACHE STRING
    "uACPI repository URL"
)
set(HAZEL_DEP_UACPI_TAG "4.0.0" CACHE STRING "uACPI git tag")

function(setup_uacpi)
    hazel_cpm_add_package(
        NAME
        uacpi
        GIT_REPOSITORY
        "${HAZEL_DEP_UACPI_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_UACPI_TAG}"
        DOWNLOAD_ONLY
        YES
    )

    set(_hazel_uacpi_source_dir "")
    if(DEFINED uacpi_SOURCE_DIR AND NOT "${uacpi_SOURCE_DIR}" STREQUAL "")
        set(_hazel_uacpi_source_dir "${uacpi_SOURCE_DIR}")
    elseif(
        DEFINED CPM_PACKAGE_uacpi_SOURCE_DIR
        AND NOT "${CPM_PACKAGE_uacpi_SOURCE_DIR}" STREQUAL ""
    )
        set(_hazel_uacpi_source_dir "${CPM_PACKAGE_uacpi_SOURCE_DIR}")
    endif()

    if("${_hazel_uacpi_source_dir}" STREQUAL "")
        message(
            FATAL_ERROR
            "uACPI was fetched, but CPM did not provide a source directory variable."
        )
    endif()

    if(NOT EXISTS "${_hazel_uacpi_source_dir}/uacpi.cmake")
        message(
            FATAL_ERROR
            "uACPI was fetched but '${_hazel_uacpi_source_dir}/uacpi.cmake' is missing."
        )
    endif()

    set(uacpi_SOURCE_DIR "${_hazel_uacpi_source_dir}" PARENT_SCOPE)
endfunction()
