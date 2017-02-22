cmake_minimum_required(VERSION 3.5)
project(firewall)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)

FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED )

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    add_executable(firewall ${SOURCE_FILES})
    target_link_libraries(firewall pcap bprinter ${Boost_LIBRARIES})
endif()