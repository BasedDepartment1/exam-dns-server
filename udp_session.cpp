#include "udp_session.hpp"
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>

namespace dns
{

UdpSession::UdpSession(const UdpSocket& socket,
    const std::size_t bufferSize /* = 1024*/)
    : socket_(socket), bufferSize_(bufferSize)
{
}

UdpSession::Bytes UdpSession::Receive()
{
    Bytes bytes{bufferSize_};
    sockaddr addr{};
    const ssize_t receivedCount = recvfrom(socket_.Handler(), &bytes[0],
        bytes.size(), 0, &addr, &clientLen_);
    if (receivedCount < 0)
    {
        throw std::runtime_error("failed to receive");
    }
    std::memcpy(&client_, &addr, sizeof(addr));
    bytes.resize(receivedCount);
    return bytes;
}

void UdpSession::Reply(const UdpSession::Bytes& bytes)
{
    sockaddr addr{};
    std::memcpy(&addr, &client_, sizeof(addr));
    const ssize_t sendCount = sendto(socket_.Handler(), bytes.data(),
        bytes.size(), 0, &addr, clientLen_);
    if (sendCount < 0 || static_cast<std::size_t>(sendCount) != bytes.size())
    {
        throw std::runtime_error("failed to send");
    }
}

} // namespace dns
