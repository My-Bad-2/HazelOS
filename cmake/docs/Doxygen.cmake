function(project_enable_doxygen DOXYGEN_THEME)
    find_package(Doxygen REQUIRED OPTIONAL_COMPONENTS dot)

    if((NOT DOXYGEN_USE_MDFILE_AS_MAINPAGE) AND EXISTS "${CMAKE_SOURCE_DIR}/README.md")
        set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md")
    endif()


    set(DOXYGEN_QUIET YES)
    set(DOXYGEN_CALLER_GRAPH YES)
    set(DOXYGEN_CALL_GRAPH YES)
    set(DOXYGEN_EXTRACT_ALL NO)
    set(DOXYGEN_GENERATE_TREEVIEW YES)

    set(DOXYGEN_DOT_IMAGE_FORMAT svg)
    set(DOXYGEN_DOT_TRANSPARENT YES)

    set(DOXYGEN_HTML_COLORSTYLE "LIGHT")

    if(NOT DOXYGEN_EXCLUDE_PATTERNS)
        set(
            DOXYGEN_EXCLUDE_PATTERNS 
            "*/_deps/*"
            "*/boot/*.h"
        )
    endif()

    set(DOXYGEN_EXCLUDE "${CMAKE_SOURCE_DIR}/cache")

    if("${DOXYGEN_THEME}" STREQUAL "")
        set(DOXYGEN_THEME "awesome-sidebar")
    endif()

    if("${DOXYGEN_THEME}" STREQUAL "awesome" OR "${DOXYGEN_THEME}" STREQUAL "awesome-sidebar")
        include(FetchContent)
        FetchContent_Declare(
            _doxygen_theme
            URL https://github.com/jothepro/doxygen-awesome-css/archive/refs/heads/main.zip
        )
        FetchContent_MakeAvailable(_doxygen_theme)

        if("${DOXYGEN_THEME}" STREQUAL "awesome" OR "${DOXYGEN_THEME}" STREQUAL "awesome-sidebar")
          set(DOXYGEN_HTML_EXTRA_STYLESHEET "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome.css")
        endif()

        if("${DOXYGEN_THEME}" STREQUAL "awesome-sidebar")
          set(
                DOXYGEN_HTML_EXTRA_STYLESHEET
                ${DOXYGEN_HTML_EXTRA_STYLESHEET}
                "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome-sidebar-only.css"
                "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome-sidebar-only-darkmode-toggle.css"
            )
        endif()

        set(
            DOXYGEN_HTML_EXTRA_FILES
            "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome-darkmode-toggle.js"
            "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome-fragment-copy-button.js"
            "${_doxygen_theme_SOURCE_DIR}/doxygen-awesome-paragraph-link.js"
        )

        set(DOXYGEN_HTML_HEADER "${CMAKE_SOURCE_DIR}/misc/docs/header.html")
        set(DOXYGEN_HTML_COPY_CLIPBOARD NO)
    else()
        # use the original doxygen theme
    endif()

    message(STATUS "Adding `doxygen-docs` target that builds the documentation.")
    doxygen_add_docs(
        doxygen-docs ALL
        ${PROJECT_SOURCE_DIR}
        COMMENT "Generating documentation - entry file: ${CMAKE_CURRENT_BINARY_DIR}/html/index.html"
    )
endfunction()