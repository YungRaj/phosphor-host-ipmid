#define FUZZING
#include "ipmid-new.cpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if(Size < 24)
        return 0;

    auto io = std::make_shared<boost::asio::io_context>();
    setIoContext(io);

    boost::asio::spawn(io, [Data, Size](boost::asio::yield_context yield) {
        unsigned char seq = 0, netFn = 0, lun = 0, cmd = 0;
        int channel, userId, rqSa, hostIdx;
        uint32_t sessionId;

        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

        seq = Data[0];
        netFn = Data[1];
        lun = Data[2];
        cmd = Data[3];

        channel = *(int*) &Data[4];
        userId = *(int*) &Data[8];
        sessionId = *(uint32_t*) &Data[12];
        rqSa = *(int*) &Data[16];
        hostIdx = *(int*) &Data[20];

        size_t NewSize = Size - 24;
        const uint8_t *NewData = Data + 24;

        ipmi::SecureBuffer secure_data;
        secure_data.assign(NewData, NewData + NewSize);
        auto ctx = std::make_shared<ipmi::Context>(
            bus, netFn, lun, cmd, channel, userId, sessionId, ipmi::Privilege::Admin, rqSa, hostIdx, yield);
        auto request = std::make_shared<ipmi::message::Request>(
            ctx, std::forward<ipmi::SecureBuffer>(secure_data));
        ipmi::message::Response::ptr response =
            ipmi::executeIpmiCommand(request);
    });

    io->run();

    return 0;
}
