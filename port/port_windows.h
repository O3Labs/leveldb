// Copyright (c) 2018 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_PORT_PORT_WINDOWS_H_
#define STORAGE_LEVELDB_PORT_PORT_WINDOWS_H_

// Prevent Windows headers from defining min/max macros and instead
// use STL.
#define NOMINMAX

#include <windows.h>

// ssize_t is a POSIX type and not a C++ type so define it.
#if defined(_WIN64)
typedef __int64 ssize_t;
#else
typedef long ssize_t;
#endif

// The rest of this port is standard C++.
#include "port_stdcxx.h"

#endif  // STORAGE_LEVELDB_PORT_PORT_WINDOWS_H_
