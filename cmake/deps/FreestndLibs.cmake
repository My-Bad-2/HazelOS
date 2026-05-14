include_guard()

set(HAZEL_DEP_FREESTND_LIBS_REPOSITORY
    https://github.com/My-Bad-2/freestnd-libs
    CACHE STRING
    "freestnd-libs repository URL"
)
set(HAZEL_DEP_FREESTND_LIBS_TAG "main" CACHE STRING "freestnd-libs git tag")

function(setup_freestnd_cxx_headers)
    hazel_cpm_add_package(
        NAME
        freestnd_libs
        GIT_REPOSITORY
        "${HAZEL_DEP_FREESTND_LIBS_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_FREESTND_LIBS_TAG}"
    )
endfunction()
