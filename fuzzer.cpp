#include "fuzzer.hpp"

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

namespace phosphor
{

using namespace std::chrono_literals;

static sd_bus* bus_connection = nullptr;
static std::shared_ptr<boost::asio::io_context> io = nullptr;
static std::shared_ptr<sdbusplus::asio::connection> sdbusp = nullptr;

int FuzzIpmidInitialize(int *argc, char ***argv) {
    sd_bus_default_system(&bus_connection);
    io = std::make_shared<boost::asio::io_context>();
    setIoContext(io);
    sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus_connection);
    setSdBus(sdbusp);
    return 0;
}

int FuzzIpmid(const uint8_t *Data, size_t Size) {
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

}

#ifdef FUZZ_ONE

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

extern "C" void __llvm_profile_write_file(void);

void handle_crash(int signum)
{
    __llvm_profile_write_file();
    std::_Exit(1);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path-to-file>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error: Could not open file: " << argv[1] << "\n";
        return 1;
    }

    signal(SIGSEGV, handle_crash);

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Error: Could not read file\n";
        return 1;
    }

    phosphor::FuzzIpmid(buffer.data(), buffer.size());
}
#endif