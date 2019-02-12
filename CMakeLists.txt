cmake_minimum_required(VERSION 3.11)
project(MyServer)

set(CMAKE_CXX_STANDARD 17)

SET(EXECUTABLE_OUTPUT_PATH "${PROJECT_BINARY_DIR}/bin")
SET(LIBRARY_OUTPUT_PATH "${PROJECT_BINARY_DIR}/lib")

add_subdirectory("${PROJECT_SOURCE_DIR}/thirdparty")
add_subdirectory("${PROJECT_SOURCE_DIR}/src")
add_subdirectory("${PROJECT_SOURCE_DIR}/test")
