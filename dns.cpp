#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <netinet/in.h>

#include "dns.hpp"

namespace dns
{

std::uint16_t Flags::GetBits(const Flags::Bits bits) const
{
    std::bitset<16> bitset{bytes};
    switch (bits)
    {
    case Bits::QR:
        return bitset[15];
    case Bits::OPCODE:
    {
        std::bitset<4> result{};
        result[0] = bitset[14];
        result[1] = bitset[13];
        result[2] = bitset[12];
        result[3] = bitset[11];
        return result.to_ulong();
    }
    case Bits::AA:
        return bitset[10];
    case Bits::TC:
        return bitset[9];
    case Bits::RD:
        return bitset[8];
    case Bits::RA:
        return bitset[7];
    case Bits::Z:
        return bitset[6];
    case Bits::AD:
        return bitset[5];
    case Bits::CD:
        return bitset[4];
    case Bits::RCODE:
    {
        std::bitset<4> result{};
        result[0] = bitset[3];
        result[1] = bitset[2];
        result[2] = bitset[1];
        result[3] = bitset[0];
        return result.to_ulong();
    }
    }
}

void Flags::SetBits(const Flags::Bits bits, const std::uint16_t value)
{
    std::bitset<16> result{bytes};
    switch (bits)
    {
    case Bits::QR:
        result[15] = value;
        break;
    case Bits::OPCODE:
    {
        std::bitset<4> bitset{value};
        result[14] = bitset[0];
        result[13] = bitset[1];
        result[12] = bitset[2];
        result[11] = bitset[3];
        break;
    }
    case Bits::AA:
        result[10] = value;
        break;
    case Bits::TC:
        result[9] = value;
        break;
    case Bits::RD:
        result[8] = value;
        break;
    case Bits::RA:
        result[7] = value;
        break;
    case Bits::Z:
        result[6] = value;
        break;
    case Bits::AD:
        result[5] = value;
        break;
    case Bits::CD:
        result[4] = value;
        break;
    case Bits::RCODE:
    {
        std::bitset<4> bitset{value};
        result[3] = bitset[0];
        result[2] = bitset[1];
        result[1] = bitset[2];
        result[0] = bitset[3];
        break;
    }
    }
    bytes = result.to_ulong();
}

Query::Query(const std::vector<std::byte>& bytes)
{
    ParseHeader(bytes);
    ParseQuestion(bytes);
}

void Query::ParseHeader(const std::vector<std::byte>& bytes)
{
    if (bytes.size() < 12)
    {
        throw std::runtime_error("insuffucient DNS query length");
    }

    std::memcpy(&header.transactionId, bytes.data(), 2);
    header.transactionId = ntohs(header.transactionId);

    std::memcpy(&header.flags, bytes.data() + 2, 2);
    header.flags.bytes = ntohs(header.flags.bytes);
    if (header.flags.GetBits(Flags::Bits::QR) != 0)
    {
        throw std::runtime_error("not a DNS query");
    }

    std::memcpy(&header.numberOfQuestions, bytes.data() + 4, 2);
    header.numberOfQuestions = ntohs(header.numberOfQuestions);
    if (header.numberOfQuestions > 1)
    {
        throw std::runtime_error("only one question is supported per query");
    }

    std::memcpy(&header.numberOfAnswers, bytes.data() + 6, 2);
    header.numberOfAnswers = ntohs(header.numberOfAnswers);

    std::memcpy(&header.numberOfAuthorityRRs, bytes.data() + 8, 2);
    header.numberOfAuthorityRRs = ntohs(header.numberOfAuthorityRRs);

    std::memcpy(&header.numberOfAuthorityRRs, bytes.data() + 10, 2);
    header.numberOfAuthorityRRs = ntohs(header.numberOfAuthorityRRs);
}

void Query::ParseQuestion(const std::vector<std::byte>& bytes)
{
    if (header.numberOfQuestions > 0 && bytes.size() < (12 + 1 + 4))
    {
        throw std::runtime_error("insufficient DNS question length");
    }

    // TODO: добавьте десериализацию секции question из массива
    // байт bytes. В первых 12 элементах массива находится
    // заголовок header, question находится сразу после него.
    // В этом методе необходимо заполнить поле this->question.
}


std::vector<std::byte> Response::Serialize() const
{
    std::vector<std::byte> bytes{};
    SerializeHeader(bytes);
    SerializeQuestion(bytes);
    return bytes;
}

void Response::SerializeHeader(std::vector<std::byte>& bytes) const
{
    bytes.resize(sizeof(header));

    std::uint16_t transactionId = htons(header.transactionId);
    std::memcpy(&bytes[0], &transactionId, 2);

    std::uint16_t flags = htons(header.flags.bytes);
    std::memcpy(&bytes[2], &flags, 2);

    std::uint16_t numberOfQuestions = htons(header.numberOfQuestions);
    std::memcpy(&bytes[4], &numberOfQuestions, 2);

    std::uint16_t numberOfAnswers = htons(header.numberOfAnswers);
    std::memcpy(&bytes[6], &numberOfAnswers, 2);

    std::uint16_t numberOfAuthorityRRs = htons(header.numberOfAuthorityRRs);
    std::memcpy(&bytes[8], &numberOfAuthorityRRs, 2);

    std::uint16_t numberOfAdditionalRRs = htons(header.numberOfAdditionalRRs);
    std::memcpy(&bytes[10], &numberOfAdditionalRRs, 2);
}

void Response::SerializeQuestion(
    [[maybe_unused]] std::vector<std::byte>& bytes) const
{
    // TODO: добавьте сериализацию поля this->question в массив
    // байтов bytes. Bytes уже содержит сериализованный заголовок
    // header, question необходимо добавить в конец массива.
}

} // namespace dns
