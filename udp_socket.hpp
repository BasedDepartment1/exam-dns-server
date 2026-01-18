#pragma once

namespace dns
{

class UdpSocket
{
public:
    explicit UdpSocket(const int port);
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket& operator=(UdpSocket&&) = delete;
    ~UdpSocket() noexcept;
    int Handler() const noexcept;

private:
    int fd_;
};

} // namespace dns
