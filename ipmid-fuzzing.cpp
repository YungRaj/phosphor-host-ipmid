#define FUZZING
#include "ipmid-new.cpp"

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

#include <iostream>
#include <future>
#include <chrono>
#include <functional>

using namespace std::chrono_literals;

static sd_bus* bus_connection = nullptr;
static std::shared_ptr<boost::asio::io_context> io = nullptr;
static std::shared_ptr<sdbusplus::asio::connection> sdbusp = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    sd_bus_default_system(&bus_connection);
    io = std::make_shared<boost::asio::io_context>();
    setIoContext(io);
    sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus_connection);
    setSdBus(sdbusp);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 24) {
        return 0;
    }

    auto result_promise = std::make_shared<std::promise<int>>();
    std::future<int> result_future = result_promise->get_future();

    boost::asio::cancellation_signal cancel;

    boost::asio::spawn(
        *io,
        [=](boost::asio::yield_context yield) {
            try {
                unsigned char seq = Data[0];
                unsigned char netFn = Data[1];
                unsigned char lun = Data[2];
                unsigned char cmd = Data[3];
                int channel = *(int*) &Data[4];
                int userId = *(int*) &Data[8];
                uint32_t sessionId = *(uint32_t*) &Data[12];
                int rqSa = *(int*) &Data[16];
                int hostIdx = *(int*) &Data[20];
                size_t NewSize = Size - 24;
                const uint8_t *NewData = Data + 24;

                ipmi::SecureBuffer secure_data;
                secure_data.assign(NewData, NewData + NewSize);
                auto ctx = std::make_shared<ipmi::Context>(
                    sdbusp, netFn, lun, cmd, channel, userId, sessionId,
                    ipmi::Privilege::Admin, rqSa, hostIdx, yield);

                auto request = std::make_shared<ipmi::message::Request>(
                    ctx, std::forward<ipmi::SecureBuffer>(secure_data));

                ipmi::message::Response::ptr response =
                    ipmi::executeIpmiCommand(request);
            } catch (const boost::system::system_error& e) {
                if (e.code() != boost::asio::error::operation_aborted) {
                    std::cerr << "An error occurred: " << e.what() << std::endl;
                    result_promise->set_value(-1);
                    return;
                }
            } catch (...) {
                std::cerr << "An unknown error occurred." << std::endl;
                result_promise->set_value(-1);
                return;
            }
            result_promise->set_value(0);
        },
        boost::asio::bind_cancellation_slot(cancel.slot(),
                                            boost::asio::detached));

    io->poll();

    if (result_future.wait_for(0ms) == std::future_status::ready) {
        return result_future.get();
    } else {
        cancel.emit(boost::asio::cancellation_type::all);
        io->poll();
        return -1;
    }
}
