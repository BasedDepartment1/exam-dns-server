#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "udp_socket.hpp"

namespace dns
{

UdpSocket::UdpSocket(const int port)
{
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0)
    {
        throw std::runtime_error("failed to open UDP socket");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    sockaddr bindAddr{};
    static_assert(sizeof(addr) == sizeof(bindAddr));
    std::memcpy(&bindAddr, &addr, sizeof(addr));

    if (bind(fd_, &bindAddr, sizeof(bindAddr)) < 0)
    {
        close(fd_);
        throw std::runtime_error("failed to bind socket to address");
    }
}

int UdpSocket::Handler() const noexcept
{
    return fd_;
}

UdpSocket::~UdpSocket() noexcept
{
    close(fd_);
}

} // namespace dns
