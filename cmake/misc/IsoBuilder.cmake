function(build_iso)
    set(oneValueArgs STAGING_DIR TRIGGER_NAME)
    set(multiValueArgs XORRISO_FLAGS)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    set(ISO_OUTPUT "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.iso")
    
    find_program(XORRISO_CMD xorriso REQUIRED)

    if(NOT XORRISO_CMD)
        message(FATAL "Xorriso not found!")
    endif()

    add_custom_command(
        OUTPUT ${ISO_OUTPUT}
        COMMAND ${XORRISO_CMD}
                ${ARG_XORRISO_FLAGS} 
                ${ARG_STAGING_DIR}
                -o ${ISO_OUTPUT}
        
        # The directory content is managed by an external target
        COMMENT "Packing ${ARG_STAGING_DIR} into ${ISO_OUTPUT}..."
        VERBATIM
    )

    # Trigger
    add_custom_target(${ARG_TRIGGER_NAME}
        DEPENDS ${ISO_OUTPUT}
    )
    
    message(STATUS "Optional Target '${ARG_TRIGGER_NAME}' registered for ${ISO_OUTPUT}")
endfunction()