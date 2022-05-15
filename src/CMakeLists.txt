cmake_minimum_required(VERSION 3.10.0)
project(Horcrux)

add_executable(Horcrux "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/classes/horcrux.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/classes/cipher.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/classes/file_manager.cpp")
target_include_directories(Horcrux PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

IF (WIN32)
    target_link_libraries(Horcrux "${CMAKE_CURRENT_SOURCE_DIR}/lib/libcrypto.lib")
ENDIF()