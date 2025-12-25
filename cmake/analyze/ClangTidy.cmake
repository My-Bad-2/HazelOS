function(add_clang_tidy_target)
    set(oneValueArgs TARGET_NAME)
    set(multiValueArgs DIRECTORIES)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    find_program(CLANG_TIDY_EXE clang-tidy)
    if(NOT CLANG_TIDY_EXE)
        message(WARNING "clang-tidy not found! Target '${ARG_TARGET_NAME}' disabled.")
        return()
    endif()

    # Find Source files
    set(FILE_EXTENSIONS "*.cpp" "*.cxx" "*.cc" "*.c")
    set(ALL_SOURCE_FILES "")

    foreach(DIR ${ARG_DIRECTORIES})
        foreach(EXT ${FILE_EXTENSIONS})
            file(GLOB_RECURSE FOUND_FILES "${DIR}/${EXT}")
            list(APPEND ALL_SOURCE_FILES ${FOUND_FILES})
        endforeach()
    endforeach()

    if(NOT ALL_SOURCE_FILES)
        return()
    endif()

    # Create "Check" Target (Reports warnings, doesn't change files)
    add_custom_target(${ARG_TARGET_NAME}
        COMMAND ${CLANG_TIDY_EXE}
                -p ${CMAKE_BINARY_DIR} # Point to build folder containing compile_commands.json
                ${ALL_SOURCE_FILES}
        COMMENT "Running clang-tidy analysis..."
        VERBATIM
    )

    # Create "Fix" Target (Automatically attempts to fix code)
    add_custom_target(${ARG_TARGET_NAME}_fix
        COMMAND ${CLANG_TIDY_EXE}
                -p ${CMAKE_BINARY_DIR}
                -fix
                -format-style=file # Reformat file
                ${ALL_SOURCE_FILES}
        COMMENT "Running clang-tidy with auto-fix..."
        VERBATIM
    )
endfunction()