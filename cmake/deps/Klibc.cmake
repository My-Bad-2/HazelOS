include_guard()

set(HAZEL_DEP_KLIBC_REPOSITORY
    "https://github.com/My-Bad-2/baremetal-libc.git"
    CACHE STRING
    "Baremetal libc repository URL"
)
set(HAZEL_DEP_KLIBC_TAG "main" CACHE STRING "Baremetal libc git tag")

function(setup_prebuilt_klibc)
    hazel_cpm_add_package(
        NAME
        klibc
        GIT_REPOSITORY
        "${HAZEL_DEP_KLIBC_REPOSITORY}"
        GIT_TAG
        "${HAZEL_DEP_KLIBC_TAG}"
    )
endfunction()
