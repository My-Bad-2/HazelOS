function(add_qemu_targets)
    set(oneValueArgs ISO_FILE)
    set(multiValueArgs COMMON_FLAGS ACCEL_FLAGS DEBUG_FLAGS)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    find_program(QEMU_CMD "qemu-system-${${PROJECT_NAME}_ARCHITECTURE}")

    if(NOT QEMU_CMD)
        return()
    endif()

    add_custom_target(
        run
        COMMAND ${QEMU_CMD}
                -cdrom ${ARG_ISO_FILE}
                -drive if=pflash,format=raw,unit=0,file=${OVMF_CODE_BINARY_PATH},readonly=on
                -drive if=pflash,format=raw,unit=1,file=${OVMF_VARS_BINARY_PATH}
                ${ARG_COMMON_FLAGS}
                ${ARG_ACCEL_FLAGS}
        DEPENDS ${ARG_ISO_FILE}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Launching QEMU (Accelerated)..."
        USES_TERMINAL
    )

    add_custom_target(
        debug
        COMMAND ${QEMU_CMD}
                -cdrom ${ARG_ISO_FILE}
                -drive if=pflash,format=raw,unit=0,file=${OVMF_CODE_BINARY_PATH},readonly=on
                -drive if=pflash,format=raw,unit=1,file=${OVMF_VARS_BINARY_PATH}
                ${ARG_COMMON_FLAGS}
                ${ARG_DEBUG_FLAGS}
                ${ARG_ACCEL_FLAGS}
        DEPENDS ${ARG_ISO_FILE}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Launching QEMU (Debug Mode - Waiting for GDB)..."
        USES_TERMINAL
    )
endfunction()