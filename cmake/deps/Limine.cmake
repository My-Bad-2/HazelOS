function(setup_limine)
    # --- 1. Set Basic Variables ---
    # Map standard arch names to Limine's EFI file naming convention
    if(${PROJECT_NAME}_ARCHITECTURE STREQUAL "x86_64")
        set(LIMINE_EFI_FILE "BOOTX64.EFI")
    else()
        message(FATAL_ERROR "Unsupported Limine Architecture: ${${PROJECT_NAME}_ARCHITECTURE}")
    endif()

    set(LIMINE_ISO_DIR ${${PROJECT_NAME}_ISO_DIR})

    # --- 2. CPM Download ---
    include(${CPM_DOWNLOAD_LOCATION})

    CPMAddPackage(
        NAME limine_artifacts
        GIT_REPOSITORY https://github.com/limine-bootloader/limine.git
        GIT_TAG v10.5.0-binary
        DOWNLOAD_ONLY YES
    )

    # --- 3. Compile Host Executable ---
    add_custom_command(
        OUTPUT ${limine_artifacts_SOURCE_DIR}/limine
        COMMAND cc -std=c99 -O2 -pipe 
                ${limine_artifacts_SOURCE_DIR}/limine.c 
                -o ${limine_artifacts_SOURCE_DIR}/limine
        COMMENT "Compiling Limine host deploy tool..."
        DEPENDS ${limine_artifacts_SOURCE_DIR}/limine.c
        VERBATIM
    )

    # Target to trigger the compilation
    add_custom_target(build_limine_tool DEPENDS ${limine_artifacts_SOURCE_DIR}/limine)

    # --- 4. Install Binaries to ISO Folder ---
    add_custom_target(install_limine
        DEPENDS build_limine_tool

        # 1. Create directory structure
        COMMAND ${CMAKE_COMMAND} -E make_directory ${LIMINE_ISO_DIR}/EFI/BOOT

        # Copy common Limine system files
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${limine_artifacts_SOURCE_DIR}/limine-bios.sys
                ${LIMINE_ISO_DIR}/boot/limine/limine-bios.sys
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${limine_artifacts_SOURCE_DIR}/limine-bios-cd.bin
                ${LIMINE_ISO_DIR}/boot/limine/limine-bios-cd.bin
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${limine_artifacts_SOURCE_DIR}/limine-uefi-cd.bin
                ${LIMINE_ISO_DIR}/boot/limine/limine-uefi-cd.bin

        # Copy the architecture specific EFI executable
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${limine_artifacts_SOURCE_DIR}/${LIMINE_EFI_FILE}
                ${LIMINE_ISO_DIR}/EFI/BOOT/${LIMINE_EFI_FILE}

        COMMENT "Installing Limine ${LIMINE_ARCH} binaries to ${LIMINE_ISO_DIR}"
    )

    add_custom_target(
        patch_limine
        DEPENDS ${${PROJECT_NAME}_ISO_FILE}
        # The command: ./limine bios-install <iso_path>
        COMMAND ${limine_artifacts_SOURCE_DIR}/limine bios-install ${${PROJECT_NAME}_ISO_FILE}
        
        COMMENT "Patching ${${PROJECT_NAME}_ISO_FILE} with Limine BIOS bootloader..."
        VERBATIM
    )
endfunction()