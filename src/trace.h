#pragma once

extern __attribute__((format(printf, 1, 2))) void trace(const char* format, ...);

#define TRACE_NO_NEWLINE(FMT, ...) trace(FMT, ##__VA_ARGS__)

#define TRACE(FMT, ...) trace(FMT "\n", ##__VA_ARGS__)

#define TRACE_WITH_INFO(FMT, ...) TRACE("[" __FILE__ ":" STRINGIFY(__LINE__) "] " FMT, ##__VA_ARGS__)
