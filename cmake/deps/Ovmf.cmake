# Define where to save the file (Cache directory is safer than build dir for persistence)
set(OVMF_INSTALL_DIR "${CMAKE_SOURCE_DIR}/cache/ovmf" CACHE PATH "Directory to store OVMF binaries")

# Map Architecture to filename
set(EDK2_NIGHTLY_URL "https://raw.githubusercontent.com/retrage/edk2-nightly/64e2e658ab728aac64591c00916d36ae649c74b0/bin/")

# Select filename based on the repository's naming convention
if(${${PROJECT_NAME}_ARCHITECTURE} STREQUAL "x86_64")
    set(OVMF_FILENAME_CODE "RELEASEX64_OVMF_CODE.fd")
    set(OVMF_FILENAME_VARS "RELEASEX64_OVMF_VARS.fd")
else()
    message(FATAL_ERROR "No OVMF mapping for ${${PROJECT_NAME}_ARCHITECTURE}")
endif()

# Full local path where the file will be saved
set(OVMF_LOCAL_PATH_CODE "${OVMF_INSTALL_DIR}/${OVMF_FILENAME_CODE}")
set(OVMF_LOCAL_PATH_VARS "${OVMF_INSTALL_DIR}/${OVMF_FILENAME_VARS}")

# Download and Verify
if(EXISTS "${OVMF_LOCAL_PATH_CODE}")
    message(STATUS "OVMF binary already exists at: ${OVMF_LOCAL_PATH_CODE}")
else()
    message(STATUS "Downloading ${OVMF_FILENAME_CODE} from edk2-nightly...")

    file(
        DOWNLOAD
        "${EDK2_NIGHTLY_URL}/${OVMF_FILENAME_CODE}"
        "${OVMF_LOCAL_PATH_CODE}"
        # SHOW_PROGRESS
        TIMEOUT 60
        STATUS DOWNLOAD_STATUS
        LOG DOWNLOAD_LOG
    )

    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    list(GET DOWNLOAD_STATUS 1 STATUS_MSG)

    if(NOT STATUS_CODE EQUAL 0)
        file(REMOVE "${OVMF_LOCAL_PATH_CODE}") # Clean up partial file
        message(FATAL_ERROR "Download failed: ${STATUS_MSG}\nLog: ${DOWNLOAD_LOG}")
    else()
        message(STATUS "Successfully downloaded to: ${OVMF_LOCAL_PATH_CODE}")
    endif()
endif()

# Download and Verify
if(EXISTS "${OVMF_LOCAL_PATH_VARS}")
    message(STATUS "OVMF binary already exists at: ${OVMF_LOCAL_PATH_VARS}")
else()
    message(STATUS "Downloading ${OVMF_FILENAME_VARS} from edk2-nightly...")

    file(
        DOWNLOAD
        "${EDK2_NIGHTLY_URL}/${OVMF_FILENAME_VARS}"
        "${OVMF_LOCAL_PATH_VARS}"
        # SHOW_PROGRESS
        TIMEOUT 60
        STATUS DOWNLOAD_STATUS
        LOG DOWNLOAD_LOG
    )

    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    list(GET DOWNLOAD_STATUS 1 STATUS_MSG)

    if(NOT STATUS_CODE EQUAL 0)
        file(REMOVE "${OVMF_LOCAL_PATH_VARS}") # Clean up partial file
        message(FATAL_ERROR "Download failed: ${STATUS_MSG}\nLog: ${DOWNLOAD_LOG}")
    else()
        message(STATUS "Successfully downloaded to: ${OVMF_LOCAL_PATH_VARS}")
    endif()
endif()

# Expose Variable for other targets
set(OVMF_CODE_BINARY_PATH "${OVMF_LOCAL_PATH_CODE}" CACHE FILEPATH "Path to the downloaded OVMF (Code) binary" FORCE)
set(OVMF_VARS_BINARY_PATH "${OVMF_LOCAL_PATH_VARS}" CACHE FILEPATH "Path to the downloaded OVMF (Vars) binary" FORCE)