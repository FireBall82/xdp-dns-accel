#pragma once
#include <string>
#include <string_view>
#include <sys/types.h>
namespace net_accel {
struct WorkerIdentity { uid_t uid; gid_t gid; std::string name; };
// Root defaults to nobody; capability-launched non-root processes retain their UID.
WorkerIdentity worker_identity(std::string_view user = {});
void drop_worker_privileges(const WorkerIdentity& identity);
void harden_process();
}
