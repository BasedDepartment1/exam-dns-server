#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns
{

struct Flags
{
    std::uint16_t bytes;
    enum class Bits
    {
        QR,
        OPCODE,
        AA,
        TC,
        RD,
        RA,
        Z,
        AD,
        CD,
        RCODE
    };
    std::uint16_t GetBits(const Bits bits) const;
    void SetBits(const Bits bits, const std::uint16_t value);
};

struct Header
{
    std::uint16_t transactionId;
    Flags flags;
    std::uint16_t numberOfQuestions;
    std::uint16_t numberOfAnswers;
    std::uint16_t numberOfAuthorityRRs;
    std::uint16_t numberOfAdditionalRRs;
};

static_assert(sizeof(Header) == 12);

struct Question
{
    std::string name;
    std::uint16_t type;
    std::uint16_t classCode;
};

struct Query
{
    Header header;
    Question question;
    explicit Query(const std::vector<std::byte>& bytes);

private:
    void ParseHeader(const std::vector<std::byte>& bytes);
    void ParseQuestion(const std::vector<std::byte>& bytes);
};

struct Response
{
    Header header;
    Question question;
    std::vector<std::byte> Serialize() const;

private:
    void SerializeHeader(std::vector<std::byte>& bytes) const;
    void SerializeQuestion(std::vector<std::byte>& bytes) const;
};

} // namespace dns
