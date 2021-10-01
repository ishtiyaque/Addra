cmake_minimum_required(VERSION 3.10)

project(Addra VERSION 1.0 LANGUAGES CXX)

# Executable will be in ./bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories( ${CMAKE_SOURCE_DIR}/../../common)

find_package(SEAL 3.5 REQUIRED)

add_executable(worker worker.cpp )
target_link_libraries(worker SEAL::seal)
target_link_libraries(worker rpc)