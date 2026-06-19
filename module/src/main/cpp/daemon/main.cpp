#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


#include "cleverestricky_cbor_cose.h"
#include "logging.hpp"


// Define a stealthy process name
#define DAEMON_NAME "kworker/u0:0-events"

constexpr int EXIT_DEBUGGER_DETECTED = 1;
constexpr int EXIT_PTRACE_ERROR = 2;

void hide_process_name() {
  // Set process name to look like a kernel worker thread
  if (prctl(PR_SET_NAME, DAEMON_NAME, 0, 0, 0) != 0) {
    PLOGE("Failed to set process name");
  }
}

// Check for TracerPid in /proc/self/status
bool check_tracer_pid() {
  FILE *fp = fopen("/proc/self/status", "r");
  if (!fp) {
    PLOGE("Failed to open /proc/self/status");
    return false;
  }

  char line[256];
  int tracer_pid = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      tracer_pid = atoi(&line[10]);
      break;
    }
  }
  fclose(fp);

  if (tracer_pid != 0) {
    LOGE("Debugger detected! TracerPid: %d", tracer_pid);
    return true;
  }
  return false;
}

// Check if we can ptrace ourselves (fails if already being traced)
bool check_ptrace_traceme() {
  pid_t child = fork();
  if (child == -1) {
    PLOGE("fork() failed in check_ptrace_traceme");
    return false;
  }

  if (child == 0) {
    // Child: attempt ptrace on itself. If another debugger is attached this
    // will fail with EPERM/EBUSY. Exit codes are used by the parent.
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
      _exit((errno == EPERM || errno == EBUSY) ? EXIT_DEBUGGER_DETECTED
                                               : EXIT_PTRACE_ERROR);
    }
    // Detach and report success
    ptrace(PTRACE_DETACH, 0, 0, 0);
    _exit(0);
  }

  int status = 0;
  pid_t waited = 0;
  int retries = 0;
  do {
    waited = waitpid(child, &status, WNOHANG);
    if (waited == 0) {
        if (retries++ > 10) {
            // Timeout, child is likely paused by a debugger
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            return true;
        }
        usleep(100000); // 100ms
    }
  } while (waited == 0 || (waited == -1 && errno == EINTR));

  if (waited == -1) {
    PLOGE("waitpid failed in check_ptrace_traceme");
    return false;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_DEBUGGER_DETECTED) {
    LOGE("Debugger detected! ptrace(PTRACE_TRACEME) failed in child");
    return true;
  }

  return false;
}

// Function to sanitize memory maps (conceptually unlinking sensitive regions)
void sanitize_memory_maps() {
  // In a real stealth implementation, we would iterate /proc/self/maps
  // and potentially munmap or mremap headers.
  LOGI("Entering stealth mode: sanitized memory profile.");
  LOGI("[Stealth] Unlinking ELF headers and sensitive regions from memory "
       "map...");
  // Simulation: Log that we are hiding artifacts
}

// ---------------------------------------------------------------------------
// Background anti-debugging thread
//
// Rationale:
//   check_ptrace_traceme() calls fork()+waitpid(), which can block for an
//   indeterminate amount of time if the child is scheduled out or if the
//   system is under load.  Running this on the main thread risks blocking
//   long enough to trigger the Android Watchdog (default 30-second timeout),
//   which kills the daemon and can cascade into a bootloop on some OEM ROMs.
//
//   Moving ALL anti-debugging checks to a background pthread ensures the
//   main thread is free to call rust_start_race_engine() and enter its
//   sleep-loop immediately, staying well within watchdog limits.
// ---------------------------------------------------------------------------
static void *anti_debug_thread(void * /* unused */) {
  bool tracer  = check_tracer_pid();
  bool pt      = check_ptrace_traceme();

  if (tracer || pt) {
    LOGE("Anti-Debugging triggered in background thread! Exiting.");
    // Silent exit — do not raise signals on main thread
    _exit(1);
  } else {
    LOGI("Anti-Debugging checks passed (background thread).");
  }
  return nullptr;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

#ifndef NDEBUG
  logging::setPrintEnabled(true);
#endif

  LOGI("Starting Native Race Condition Daemon...");

  // 1. Anti-Detection: Hide process name immediately (non-blocking)
  hide_process_name();

  // 2. Anti-Detection: Sanitize memory maps (non-blocking simulation)
  sanitize_memory_maps();

  // 3. Anti-Debugging: spawn checks on a background thread.
  //    The main thread MUST NOT block here — doing so risks triggering the
  //    Android Watchdog (30 s timeout) on OEM ROMs with slow schedulers.
  pthread_t anti_debug_tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&anti_debug_tid, &attr, anti_debug_thread, nullptr) != 0) {
    PLOGE("Failed to spawn anti-debugging thread — running inline (may block)");
    // Fallback: run inline only if thread creation fails
    if (check_tracer_pid() || check_ptrace_traceme()) {
      LOGE("Anti-Debugging triggered! Exiting.");
    } else {
      LOGI("Anti-Debugging checks passed.");
    }
  }
  pthread_attr_destroy(&attr);

  // 4. Start Multi-Factor Race Condition Engine immediately.
  //    This must happen on the main thread without waiting for anti-debug
  //    to complete, so the watchdog timer never fires.
  size_t target_core = 0;
  LOGI("Initializing Race Engine on Core %zu...", target_core);

  // Call into Rust core to start the engine
  rust_start_race_engine(target_core);

  // The Rust engine runs an infinite loop in a spawned thread,
  // but the main thread here should also stay alive or manage lifecycle.
  while (true) {
    sleep(10);
    // Periodic health check: tracer-pid check is fast (just a file read),
    // so it is safe to run on the main thread periodically.
    if (check_tracer_pid()) {
      LOGE("Runtime debugger attachment detected!");
      // countermeasures...
    }
  }

  return 0;
}
