#include "process_security.hpp"
#include <cerrno>
#include <cstring>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace net_accel {
namespace {
void failure(const char* action) { throw std::runtime_error(std::string(action) + ": " + std::strerror(errno)); }
}
WorkerIdentity worker_identity(std::string_view user) {
    passwd* entry = user.empty() ? (geteuid() == 0 ? getpwnam("nobody") : getpwuid(geteuid()))
                                 : getpwnam(std::string(user).c_str());
    if (!entry || entry->pw_uid == 0) throw std::invalid_argument("--run-as must name an existing non-root user");
    if (geteuid() != 0 && (entry->pw_uid != geteuid() || entry->pw_gid != getegid()))
        throw std::invalid_argument("only root can select a different worker identity");
    return {entry->pw_uid, entry->pw_gid, entry->pw_name};
}
void harden_process() {
    rlimit core{0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)) failure("process hardening failed");
}
void drop_worker_privileges(const WorkerIdentity& identity) {
    if (!identity.uid) throw std::invalid_argument("worker UID must be non-root");
    if (geteuid() == 0 && setgroups(0, nullptr)) failure("clear supplementary groups");
    if (setresgid(identity.gid, identity.gid, identity.gid) || setresuid(identity.uid, identity.uid, identity.uid))
        failure("drop worker identity");
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    __user_cap_data_struct caps[2]{};
    if (syscall(SYS_capset, &header, caps)) failure("clear worker capabilities");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L)) failure("clear ambient capabilities");
    // Credential changes can reset dumpability. Reapply after changing UID/GID.
    harden_process();
    if (geteuid() != identity.uid || getegid() != identity.gid) throw std::runtime_error("worker identity mismatch");
}
}
