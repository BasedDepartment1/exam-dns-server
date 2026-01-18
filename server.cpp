#include <bitset>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>

#include <poll.h>
#include <netinet/in.h>

#include "server.hpp"
#include "udp_session.hpp"
#include "udp_socket.hpp"
#include "dns.hpp"

namespace dns
{

Server::Server(const int port, const std::atomic<bool>& running)
    : running_(running), socket_(port), session_(socket_)
{
    std::cout << "Listening on port " << port << '\n';
}

void Server::Run()
{
    pollfd handlers[1] = {{socket_.Handler(), POLLIN, 0}};

    while (running_.load())
    {
        const int timeoutMs = 100;
        const int pollResult = poll(handlers, 1, timeoutMs);

        if (pollResult < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            throw std::runtime_error("failed to poll");
        }
        else if (pollResult == 0)
        {
            continue;
        }
        else if (handlers[0].revents & POLLIN)
        {
            ProcessQuery();
        }
    }
}

void Server::ProcessQuery()
{
    try
    {
        const auto income{session_.Receive()};
        const Query query{income};

        std::cout << "Processing query with:\n"
                  << "\tTransaction ID: " << query.header.transactionId << '\n'
                  << "\tNumber of Questions: " << query.header.numberOfQuestions
                  << '\n'
                  << "\tQuestion name: " << query.question.name << '\n';

        auto response = MakeResponse(query);
        UdpSession::Bytes outcome{response.Serialize()};
        session_.Reply(outcome);
    }
    catch (const std::exception& err)
    {
        std::cerr << "Error while processing income: " << err.what() << '\n';
    }
}

Response Server::MakeResponse(const Query& query)
{
    Response response{};
    response.header.transactionId = query.header.transactionId;
    response.header.flags.SetBits(Flags::Bits::QR, 1);
    response.header.flags.SetBits(Flags::Bits::OPCODE,
        query.header.flags.GetBits(Flags::Bits::OPCODE));
    response.header.flags.SetBits(Flags::Bits::AA, 1);
    response.header.flags.SetBits(Flags::Bits::TC, 0);
    response.header.flags.SetBits(Flags::Bits::RD,
        query.header.flags.GetBits(Flags::Bits::RD));
    response.header.flags.SetBits(Flags::Bits::RA, 0);
    response.header.flags.SetBits(Flags::Bits::Z, 0);
    response.header.flags.SetBits(Flags::Bits::RCODE, 3);
    response.header.numberOfQuestions = 1;
    response.header.numberOfAnswers = 0;
    response.header.numberOfAuthorityRRs = 0;
    response.header.numberOfAdditionalRRs = 0;
    response.question = query.question;
    return response;
}

} // namespace dns
