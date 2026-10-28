#include "dns_protocol.hpp"
using namespace net_accel;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 65535) return 0;
    View input(data, size);
    if (auto q = parse_query(input)) {
        auto error = error_response(*q, 2);
        (void)fit_response(*q, error, 512);
        (void)cache_ttl(*q, error);
        restore_question(*q, error);
        // Exercise the upstream echo layout as well as synthesized expanded
        // questions, particularly compressed names embedded in binary labels.
        Bytes echo(input.begin(), input.end());
        write16(echo, 2, read16(echo, 2) | 0x8000);
        (void)valid_response(*q, echo);
        (void)restore_question(*q, echo);
    }
    const Bytes seed{0,1,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1};
    auto q = parse_query(seed);
    (void)valid_response(*q, input);
    (void)cache_ttl(*q, input);
    Bytes copy(input.begin(), input.end());
    (void)age_response(copy, size ? data[0] : 0);
    (void)restore_question(*q, copy);
    if (size >= 12) (void)fit_response(*q, input, 512);
    return 0;
}
