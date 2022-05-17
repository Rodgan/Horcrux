cmake_minimum_required(VERSION 3.10.0)

set (This horcrux)
project(${This})

set (
    Sources
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/classes/horcrux.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/classes/cipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/classes/file_manager.cpp
)

set (
    Headers
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(
    WinLibraries
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/Windows/libcrypto.lib
)

set(
    LinuxLibraries
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/Linux/libcrypto.a
    ${CMAKE_DL_LIBS}
)

add_executable(${This} ${Sources})
target_include_directories(${This} PUBLIC ${Headers})

IF (WIN32)
    target_link_libraries(${This} ${WinLibraries})
ELSE()
    target_link_libraries(${This} ${LinuxLibraries})
ENDIF()