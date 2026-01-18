#pragma once

#include <cstddef>
#include <vector>

#include <netinet/in.h>

#include "udp_socket.hpp"

namespace dns
{

class UdpSession
{
public:
    using Bytes = std::vector<std::byte>;
    UdpSession(const UdpSocket& socket, const std::size_t bufferSize = 1024);
    Bytes Receive();
    void Reply(const Bytes& bytes);

private:
    const UdpSocket& socket_;
    const std::size_t bufferSize_;
    sockaddr_in client_;
    socklen_t clientLen_ = sizeof(client_);
};

} // namespace dns
