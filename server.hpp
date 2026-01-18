#pragma once

#include <atomic>

#include "udp_session.hpp"
#include "udp_socket.hpp"
#include "dns.hpp"

namespace dns
{

class Server
{
public:
    Server(const int port, const std::atomic<bool>& running);
    void Run();
    void Stop();

private:
    void ProcessQuery();
    static Response MakeResponse(const Query& query);

private:
    const std::atomic<bool>& running_;
    UdpSocket socket_;
    UdpSession session_;
};

} // namespace dns
