include(${CPM_DOWNLOAD_LOCATION})

CPMAddPackage(
    NAME uacpi
    GIT_REPOSITORY https://github.com/uACPI/uACPI.git
    GIT_TAG 3.2.0
    DOWNLOAD_ONLY YES
)