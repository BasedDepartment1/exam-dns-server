cmake_minimum_required(VERSION 3.10)
project(dns_server)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_executable(dns_server)
target_sources(dns_server PRIVATE
  main.cpp
  udp_session.cpp
  udp_session.hpp
  udp_socket.cpp
  udp_socket.hpp
  server.cpp
  server.hpp
  dns.hpp
  dns.cpp
)
