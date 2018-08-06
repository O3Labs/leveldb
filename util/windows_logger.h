// Copyright (c) 2018 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Logger implementation that can be shared by all environments
// where enough posix functionality is available.

#ifndef STORAGE_LEVELDB_UTIL_WINDOWS_LOGGER_H_
#define STORAGE_LEVELDB_UTIL_WINDOWS_LOGGER_H_

#include <stdio.h>
#include <time.h>
#include <algorithm>
#include <thread>
#include "leveldb/env.h"

namespace leveldb {

class WindowsLogger : public Logger {
 private:
  FILE* file_;

 public:
  WindowsLogger(FILE* f) : file_(f) {}
  virtual ~WindowsLogger() { fclose(file_); }
  virtual void Logv(const char* format, va_list ap) {
    const std::thread::id thread_id = std::this_thread::get_id();

    // We try twice: the first time with a fixed-size stack allocated buffer,
    // and the second time with a much larger dynamically allocated buffer.
    char buffer[500];
    for (int iter = 0; iter < 2; iter++) {
      char* base;
      int bufsize;
      if (iter == 0) {
        bufsize = sizeof(buffer);
        base = buffer;
      } else {
        bufsize = 30000;
        base = new char[bufsize];
      }
      char* p = base;
      char* limit = base + bufsize;

      SYSTEMTIME t;
      GetLocalTime(&t);
      std::stringstream ss;
      ss << std::this_thread::get_id();
      p += snprintf(p, limit - p, "%04u/%02u/%02u-%02u:%02u:%02u.%06u %llx ",
                    t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
                    static_cast<int>(t.wMilliseconds * 1000),
                    std::stoull(ss.str()));

      // Print the message
      if (p < limit) {
        va_list backup_ap;
        va_copy(backup_ap, ap);
        p += vsnprintf(p, limit - p, format, backup_ap);
        va_end(backup_ap);
      }

      // Truncate to available space if necessary
      if (p >= limit) {
        if (iter == 0) {
          continue;  // Try again with larger buffer
        } else {
          p = limit - 1;
        }
      }

      // Add newline if necessary
      if (p == base || p[-1] != '\n') {
        *p++ = '\n';
      }

      assert(p <= limit);
      fwrite(base, 1, p - base, file_);
      fflush(file_);
      if (base != buffer) {
        delete[] base;
      }
      break;
    }
  }
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_UTIL_WINDOWS_LOGGER_H_
