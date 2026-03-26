cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(EasyProxy)

include_directories(
        include
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
    link_directories(x64)
    file(COPY "${PROJECT_SOURCE_DIR}/x64/WinDivert.dll" "${PROJECT_SOURCE_DIR}/x64/WinDivert64.sys" DESTINATION "${PROJECT_SOURCE_DIR}")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits
    link_directories(x86)
    file(COPY "${PROJECT_SOURCE_DIR}/x86/WinDivert.dll" "${PROJECT_SOURCE_DIR}/x86/WinDivert32.sys" "${PROJECT_SOURCE_DIR}/x86/WinDivert64.sys" DESTINATION "${PROJECT_SOURCE_DIR}")
endif()


add_executable(EasyProxy
        main.cpp
        EasyProxy.cpp
        Logger.cpp
)

target_compile_definitions(EasyProxy PRIVATE WIN32_LEAN_AND_MEAN)

target_link_libraries(EasyProxy PRIVATE
        WinDivert.lib
        ws2_32
)


set_target_properties(EasyProxy PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
)

