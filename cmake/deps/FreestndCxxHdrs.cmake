include(${CPM_DOWNLOAD_LOCATION})

CPMAddPackage(
    NAME freestnd_hdrs
    GIT_REPOSITORY https://codeberg.org/OSDev/freestnd-cxx-hdrs.git
    GIT_TAG trunk
    DOWNLOAD_ONLY YES
)

set(FREESTND_HDRS_DIR "${freestnd_hdrs_SOURCE_DIR}/${${PROJECT_NAME}_ARCHITECTURE}/include")