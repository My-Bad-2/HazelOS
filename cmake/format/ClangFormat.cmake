function(add_clang_format_target)
    set(oneValueArgs TARGET_NAME)
    set(multiValueArgs DIRECTORIES)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    find_program(CLANG_FORMAT_EXE clang-format)

    if(NOT CLANG_FORMAT_EXE)
        message(WARNING "clang-format not found! The '${ARG_TARGET_NAME}' target will be unavailable.")
        return()
    endif()

    set(FILE_EXTENSIONS 
        "*.cpp" "*.cxx" "*.cc" "*.c" 
        "*.hpp" "*.hxx" "*.hh" "*.h"
    )

    # Loop through directories and gather files
    set(ALL_SOURCE_FILES "")
    foreach(DIR ${ARG_DIRECTORIES})
        foreach(EXT ${FILE_EXTENSIONS})
            # GLOB_RECURSE finds files in subdirectories too
            file(GLOB_RECURSE FOUND_FILES "${DIR}/${EXT}")
            list(APPEND ALL_SOURCE_FILES ${FOUND_FILES})
        endforeach()
    endforeach()

    # Avoid creating a target with no files (cmake error)
    if(NOT ALL_SOURCE_FILES)
        message(STATUS "No sources found for clang-format in given directories.")
        return()
    endif()

    # Create the 'format' target (In-place edit)
    add_custom_target(${ARG_TARGET_NAME}
        COMMAND ${CLANG_FORMAT_EXE} 
                -i # In-place edit
                -style=file # Looks for .clang-format file
                ${ALL_SOURCE_FILES}
        COMMENT "Running clang-format on ${ARG_TARGET_NAME} sources..."
        VERBATIM
    )

    # Create a 'check-format' target for CI (Returns error if bad)
    add_custom_target(${ARG_TARGET_NAME}_check
        COMMAND ${CLANG_FORMAT_EXE} 
                --dry-run # Don't edit, just check
                --Werror  # Return error code if formatting is needed
                -style=file 
                ${ALL_SOURCE_FILES}
        COMMENT "Checking code formatting compliance..."
        VERBATIM
    )
endfunction()