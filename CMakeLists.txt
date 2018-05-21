cmake_minimum_required(VERSION 3.10)
project(GroupCommu)

set(CMAKE_CXX_STANDARD 11)

set(INC_DIR include)
set(LINK_DIR lib)
include_directories(${INC_DIR})

link_directories(${LINK_DIR})
link_libraries(gmp)
link_libraries(ntl)
link_libraries(mmx)

add_executable(GroupCommu main.cpp
        common.h
        GM.h
        GM.cpp
        gm_top.cpp
        m_top.cpp
        main.cpp
        Member.cpp
        Member.h
        SHA512.cpp
        SHA512.h
        SK.cpp
        TCPClient.cpp
        TCPClient.h
        TCPServer.h
        TCPServer.cpp
        )
add_custom_target(libmmx
        /usr/bin/make -C "${CMAKE_CURRENT_SOURCE_DIR}/lib/MMXlib/")
target_link_libraries(GroupCommu gmp)
target_link_libraries(GroupCommu mmx)
target_link_libraries(GroupCommu ntl)