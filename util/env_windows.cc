// Copyright (c) 2018 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "leveldb/env.h"
#include "leveldb/slice.h"
#include "port/port.h"
#include "port/thread_annotations.h"
#include "util/env_windows_test_helper.h"
#include "util/logging.h"
#include "util/mutexlock.h"
#include "util/windows_logger.h"

namespace leveldb {

namespace {

static int mmap_limit = -1;
constexpr const size_t kBufSize = 65536;

static std::string GetWindowsErrorMessage(DWORD err) {
  LPTSTR error_text(nullptr);
  DWORD buf_len = FormatMessage(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR)&error_text, 0, nullptr);
  if (!error_text) {
    return std::string();
  }
  std::string message(error_text, error_text + buf_len);
  LocalFree(error_text);
  return message;
}

static Status WindowsError(const std::string& context, DWORD err) {
  if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
    return Status::NotFound(context, GetWindowsErrorMessage(err));
  return Status::IOError(context, GetWindowsErrorMessage(err));
}

#if defined(UNICODE)
using String = std::wstring;
std::string EncodeUTF8(const std::wstring& wstr) {
  if (wstr.empty()) return std::string();
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(),
                                        NULL, 0, NULL, NULL);
  std::string encoded_str(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &encoded_str[0],
                      size_needed, NULL, NULL);
  return encoded_str;
}
std::wstring DecodeUTF8(const std::string& str) {
  if (str.empty()) return std::wstring();
  int size_needed =
      MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
  std::wstring decoded_str(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &decoded_str[0],
                      size_needed);
  return decoded_str;
}
#else
using String = std::string;
std::string EncodeUTF8(const std::string& str) { return str; }
std::string DecodeUTF8(const std::string& str) { return str; }
#endif

class ScopedHandle {
 public:
  ScopedHandle(HANDLE handle) : handle_(handle) {}
  ScopedHandle(ScopedHandle&& other) : handle_(other.Take()) {}
  ~ScopedHandle() { Close(); }

  ScopedHandle& operator=(ScopedHandle&& rhs) {
    if (this != &rhs) handle_ = rhs.Take();
    return *this;
  }

  bool Close() {
    if (!is_valid()) return true;
    HANDLE h = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return ::CloseHandle(h);
  }

  bool is_valid() const {
    return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
  }

  HANDLE get() const { return handle_; }

  HANDLE Take() {
    HANDLE h = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return h;
  }

 private:
  HANDLE handle_;
};

// Helper class to limit resource usage to avoid exhaustion.
// Currently used to limit mmap file usage so that we do not end
// up running out virtual memory, or running into kernel performance
// problems for very large databases.
class Limiter {
 public:
  // Limit maximum number of resources to |n|.
  Limiter(intptr_t n) { SetAllowed(n); }

  // If another resource is available, acquire it and return true.
  // Else return false.
  bool Acquire() LOCKS_EXCLUDED(mu_) {
    if (GetAllowed() <= 0) {
      return false;
    }
    MutexLock l(&mu_);
    intptr_t x = GetAllowed();
    if (x <= 0) {
      return false;
    } else {
      SetAllowed(x - 1);
      return true;
    }
  }

  // Release a resource acquired by a previous call to Acquire() that returned
  // true.
  void Release() LOCKS_EXCLUDED(mu_) {
    MutexLock l(&mu_);
    SetAllowed(GetAllowed() + 1);
  }

 private:
  port::Mutex mu_;
  port::AtomicPointer allowed_;

  intptr_t GetAllowed() const {
    return reinterpret_cast<intptr_t>(allowed_.Acquire_Load());
  }

  void SetAllowed(intptr_t v) EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    allowed_.Release_Store(reinterpret_cast<void*>(v));
  }

  Limiter(const Limiter&);
  void operator=(const Limiter&);
};

class WindowsSequentialFile : public SequentialFile {
 private:
  std::string filename_;
  ScopedHandle file_;

 public:
  WindowsSequentialFile(const std::string& fname, ScopedHandle file)
      : filename_(fname), file_(std::move(file)) {}
  ~WindowsSequentialFile() override {}

  Status Read(size_t n, Slice* result, char* scratch) override {
    Status s;
    DWORD bytes_read;
    if (ReadFile(file_.get(), scratch, static_cast<DWORD>(n), &bytes_read,
                 nullptr)) {
      *result = Slice(scratch, bytes_read);
    } else {
      s = WindowsError(filename_, GetLastError());
    }
    return s;
  }

  Status Skip(uint64_t n) override {
    LARGE_INTEGER distance;
    distance.QuadPart = n;
    if (!SetFilePointerEx(file_.get(), distance, nullptr, FILE_CURRENT)) {
      return WindowsError(filename_, GetLastError());
    }
    return Status::OK();
  }
};

class WindowsRandomAccessFile : public RandomAccessFile {
 private:
  std::string filename_;
  ScopedHandle handle_;

 public:
  WindowsRandomAccessFile(const std::string& fname, ScopedHandle handle)
      : filename_(fname), handle_(std::move(handle)) {}

  ~WindowsRandomAccessFile() override = default;

  Status Read(uint64_t offset, size_t n, Slice* result,
              char* scratch) const override {
    DWORD bytes_read(0);
    OVERLAPPED overlapped = {0};

    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);
    SetLastError(0);
    if (!ReadFile(handle_.get(), scratch, static_cast<DWORD>(n), &bytes_read,
                  &overlapped)) {
      DWORD err = GetLastError();
      if (err != ERROR_HANDLE_EOF) {
        *result = Slice(scratch, 0);
        return Status::IOError(filename_, GetWindowsErrorMessage(err));
      }
    }

    *result = Slice(scratch, bytes_read);
    return Status::OK();
  }
};

class WindowsMmapReadableFile : public RandomAccessFile {
 private:
  std::string filename_;
  void* mmapped_region_;
  size_t length_;
  Limiter* limiter_;

 public:
  // base[0,length-1] contains the mmapped contents of the file.
  WindowsMmapReadableFile(const std::string& fname, void* base, size_t length,
                          Limiter* limiter)
      : filename_(fname),
        mmapped_region_(base),
        length_(length),
        limiter_(limiter) {}

  ~WindowsMmapReadableFile() override {
    UnmapViewOfFile(mmapped_region_);
    limiter_->Release();
  }

  Status Read(uint64_t offset, size_t n, Slice* result,
              char* scratch) const override {
    Status s;
    if (offset + n > length_) {
      *result = Slice();
      s = WindowsError(filename_, EINVAL);
    } else {
      *result = Slice(reinterpret_cast<char*>(mmapped_region_) + offset, n);
    }
    return s;
  }
};

class WindowsWritableFile : public WritableFile {
 private:
  // buf_[0, pos_-1] contains data to be written to handle_.
  std::string filename_;
  ScopedHandle handle_;
  char buf_[kBufSize];
  size_t pos_;

 public:
  WindowsWritableFile(const std::string& fname, ScopedHandle handle)
      : filename_(fname), handle_(std::move(handle)), pos_(0) {}

  ~WindowsWritableFile() {}

  Status Append(const Slice& data) override {
    size_t n = data.size();
    const char* p = data.data();

    // Fit as much as possible into buffer.
    size_t copy = std::min(n, kBufSize - pos_);
    memcpy(buf_ + pos_, p, copy);
    p += copy;
    n -= copy;
    pos_ += copy;
    if (n == 0) {
      return Status::OK();
    }

    // Can't fit in buffer, so need to do at least one write.
    Status s = FlushBuffered();
    if (!s.ok()) {
      return s;
    }

    // Small writes go to buffer, large writes are written directly.
    if (n < kBufSize) {
      memcpy(buf_, p, n);
      pos_ = n;
      return Status::OK();
    }
    return WriteRaw(p, n);
  }

  Status Close() override {
    Status result = FlushBuffered();
    if (!handle_.Close() && result.ok()) {
      result = WindowsError(filename_, GetLastError());
    }
    return result;
  }

  Status Flush() override { return FlushBuffered(); }

  Status Sync() override {
    // On Windows no need to sync parent directory. It's metadata will be
    // updated via the creation of the new file, without an explicit sync.
    return FlushBuffered();
  }

 private:
  Status FlushBuffered() {
    Status s = WriteRaw(buf_, pos_);
    pos_ = 0;
    return s;
  }

  Status WriteRaw(const char* p, size_t n) {
    DWORD bytes_written;
    if (!WriteFile(handle_.get(), p, static_cast<DWORD>(n), &bytes_written,
                   nullptr)) {
      return Status::IOError(filename_, GetWindowsErrorMessage(GetLastError()));
    }
    return Status::OK();
  }
};

// Lock or unlock the entire file as specified by |lock|. Returns true
// when successful, false upon failure. Caller should call GetLastError()
// to determine cause of failure
static bool LockOrUnlock(HANDLE handle, bool lock) {
  if (lock) {
    return LockFile(handle,
                    /*dwFileOffsetLow=*/0, /*dwFileOffsetHigh=*/0,
                    /*nNumberOfBytesToLockLow=*/MAXDWORD,
                    /*nNumberOfBytesToLockHigh=*/MAXDWORD);
  } else {
    return UnlockFile(handle,
                      /*dwFileOffsetLow=*/0, /*dwFileOffsetHigh=*/0,
                      /*nNumberOfBytesToLockLow=*/MAXDWORD,
                      /*nNumberOfBytesToLockHigh=*/MAXDWORD);
  }
}

class WindowsFileLock : public FileLock {
 public:
  WindowsFileLock(ScopedHandle handle, const std::string& name)
      : handle_(std::move(handle)), name_(name) {}
  ScopedHandle handle_;
  std::string name_;
};

// Set of locked files.  We keep a separate set instead of just
// relying on fcntrl(F_SETLK) since fcntl(F_SETLK) does not provide
// any protection against multiple uses from the same process.
class WindowsLockTable {
 private:
  port::Mutex mu_;
  std::set<std::string> locked_files_ GUARDED_BY(mu_);

 public:
  bool Insert(const std::string& fname) LOCKS_EXCLUDED(mu_) {
    MutexLock l(&mu_);
    return locked_files_.insert(fname).second;
  }
  void Remove(const std::string& fname) LOCKS_EXCLUDED(mu_) {
    MutexLock l(&mu_);
    locked_files_.erase(fname);
  }
};

class WindowsEnv : public Env {
 public:
  WindowsEnv();
  ~WindowsEnv() override {
    char msg[] = "Destroying Env::Default()\n";
    fwrite(msg, 1, sizeof(msg), stderr);
    abort();
  }

  Status NewSequentialFile(const std::string& fname,
                           SequentialFile** result) override {
    *result = nullptr;
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), GENERIC_READ, FILE_SHARE_READ,
                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      return WindowsError(fname, GetLastError());
    }
    *result = new WindowsSequentialFile(fname, std::move(handle));
    return Status::OK();
  }

  Status NewRandomAccessFile(const std::string& fname,
                             RandomAccessFile** result) override {
    *result = nullptr;
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), GENERIC_READ, FILE_SHARE_READ,
                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      return WindowsError(fname, GetLastError());
    }
    if (!mmap_limit_.Acquire()) {
      *result = new WindowsRandomAccessFile(fname, std::move(handle));
      return Status::OK();
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(handle.get(), &li)) {
      return WindowsError(fname, GetLastError());
    }

    ScopedHandle mapping =
        CreateFileMapping(handle.get(),
                          /*security attributes=*/nullptr, PAGE_READONLY,
                          /*dwMaximumSizeHigh=*/0,
                          /*dwMaximumSizeLow=*/0, nullptr);
    if (mapping.is_valid()) {
      void* base = MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0);
      if (base) {
        *result = new WindowsMmapReadableFile(
            fname, base, static_cast<size_t>(li.QuadPart), &mmap_limit_);
        return Status::OK();
      }
    }
    Status s = WindowsError(fname, GetLastError());

    if (!s.ok()) {
      mmap_limit_.Release();
    }
    return s;
  }

  Status NewWritableFile(const std::string& fname,
                         WritableFile** result) override {
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), GENERIC_WRITE, 0, nullptr,
                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      *result = nullptr;
      return WindowsError(fname, GetLastError());
    }

    *result = new WindowsWritableFile(fname, std::move(handle));
    return Status::OK();
  }

  Status NewAppendableFile(const std::string& fname,
                           WritableFile** result) override {
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), FILE_APPEND_DATA, 0, nullptr,
                   OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      *result = nullptr;
      return WindowsError(fname, GetLastError());
    }

    *result = new WindowsWritableFile(fname, std::move(handle));
    return Status::OK();
  }

  bool FileExists(const std::string& fname) override {
    return GetFileAttributes(DecodeUTF8(fname).c_str()) !=
           INVALID_FILE_ATTRIBUTES;
  }

  Status GetChildren(const std::string& dir,
                     std::vector<std::string>* result) override {
    std::string find_str = dir + "\\*";
    WIN32_FIND_DATAA find_data;
    HANDLE dir_handle = FindFirstFileA(find_str.c_str(), &find_data);
    if (dir_handle == INVALID_HANDLE_VALUE) {
      DWORD last_error = GetLastError();
      if (last_error == ERROR_FILE_NOT_FOUND) return Status::OK();
      return WindowsError(dir, last_error);
    }
    do {
      char base_name[_MAX_FNAME];
      char ext[_MAX_EXT];

      if (!_splitpath_s(find_data.cFileName, nullptr, 0, nullptr, 0, base_name,
                        ARRAYSIZE(base_name), ext, ARRAYSIZE(ext))) {
        result->push_back(std::string(base_name) + ext);
      }
    } while (FindNextFileA(dir_handle, &find_data));
    DWORD last_error = GetLastError();
    FindClose(dir_handle);
    if (last_error != ERROR_NO_MORE_FILES) return WindowsError(dir, last_error);
    return Status::OK();
  }

  Status DeleteFile(const std::string& fname) override {
    if (!::DeleteFile(DecodeUTF8(fname).c_str()))
      return WindowsError(fname, GetLastError());
    return Status::OK();
  }

  Status CreateDir(const std::string& name) override {
    if (!CreateDirectory(DecodeUTF8(name).c_str(), nullptr))
      return WindowsError(name, GetLastError());
    return Status::OK();
  }

  Status DeleteDir(const std::string& name) override {
    if (!RemoveDirectory(DecodeUTF8(name).c_str()))
      return WindowsError(name, GetLastError());
    return Status::OK();
  }

  Status GetFileSize(const std::string& fname, uint64_t* size) override {
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), GENERIC_READ, FILE_SHARE_READ,
                   /*lpSecurityAttributes=*/nullptr, OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      *size = 0;
      return WindowsError(fname, GetLastError());
    }
    LARGE_INTEGER li;
    if (!GetFileSizeEx(handle.get(), &li)) {
      *size = 0;
      return WindowsError(fname, GetLastError());
    }
    *size = li.QuadPart;
    return Status::OK();
  }

  Status RenameFile(const std::string& src,
                    const std::string& target) override {
    String win_src = DecodeUTF8(src);
    String win_target = DecodeUTF8(target);
    if (::MoveFile(win_src.c_str(), win_target.c_str())) return Status::OK();
    if (!::ReplaceFile(win_target.c_str(), win_src.c_str(), nullptr,
                       REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
      DWORD dwErr = GetLastError();
      if (dwErr != 2) fprintf(stderr, "err Replace: %u\n", dwErr);
      return WindowsError(src, dwErr);
    }

    return Status::OK();
  }

  Status LockFile(const std::string& fname, FileLock** lock) override {
    *lock = nullptr;
    Status result;
    ScopedHandle handle =
        CreateFile(DecodeUTF8(fname).c_str(), GENERIC_READ | GENERIC_WRITE,
                   FILE_SHARE_READ,
                   /*lpSecurityAttributes=*/nullptr, OPEN_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!handle.is_valid()) {
      result = WindowsError(fname, GetLastError());
    } else if (!locks_.Insert(fname)) {
      result = Status::IOError("lock " + fname, "already held by process");
    } else if (!LockOrUnlock(handle.get(), true)) {
      result = WindowsError("lock " + fname, GetLastError());
      locks_.Remove(fname);
    } else {
      *lock = new WindowsFileLock(std::move(handle), fname);
    }
    return result;
  }

  Status UnlockFile(FileLock* lock) override {
    std::unique_ptr<WindowsFileLock> my_lock(
        reinterpret_cast<WindowsFileLock*>(lock));
    Status result;
    if (!LockOrUnlock(my_lock->handle_.get(), false)) {
      result = WindowsError("unlock", GetLastError());
    }
    locks_.Remove(my_lock->name_);
    return result;
  }

  void Schedule(void (*function)(void*), void* arg) override;

  void StartThread(void (*function)(void* arg), void* arg) override {
    std::thread t(function, arg);
    t.detach();
  }

  Status GetTestDirectory(std::string* result) override {
    const char* env = getenv("TEST_TMPDIR");
    if (env && env[0] != '\0') {
      *result = env;
      return Status::OK();
    }

    TCHAR tmp_path[MAX_PATH];
    if (!GetTempPath(ARRAYSIZE(tmp_path), tmp_path))
      return WindowsError("GetTempPath", GetLastError());
    std::stringstream ss;
    ss << EncodeUTF8(tmp_path) << "leveldbtest-" << std::this_thread::get_id();
    *result = ss.str();

    // Directory may already exist
    CreateDir(*result);
    return Status::OK();
  }

  Status NewLogger(const std::string& fname, Logger** result) override {
    FILE* f;
    errno_t err = fopen_s(&f, fname.c_str(), "w");
    if (err) return WindowsError("NewLogger", err);
    *result = new WindowsLogger(f);
    return Status::OK();
  }

  uint64_t NowMicros() override {
    // GetSystemTimeAsFileTime typically has a resolution of 10-20 msec. May
    // need to switch to a higher resolution function (QueryPerformanceCounter)
    // if greater accuracy is needed.
    FILETIME ft;
    ::GetSystemTimeAsFileTime(&ft);
    // Each tick represents a 100-nanosecond intervals since January 1, 1601
    // (UTC).
    uint64_t num_ticks =
        (static_cast<uint64_t>(ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
    return num_ticks / 10;
  }

  void SleepForMicroseconds(int micros) override {
    // TODO: Do we need a sub millisecond sleep implementation?
    ::Sleep(micros / 1000);
  }

 private:
  // BGThread() is the body of the background thread
  void BGThread();

  std::mutex mu_;
  std::condition_variable bgsignal_;
  bool started_bgthread_;

  // Entry per Schedule() call
  struct BGItem {
    void* arg;
    void (*function)(void*);
  };
  typedef std::deque<BGItem> BGQueue;
  BGQueue queue_;

  WindowsLockTable locks_;
  Limiter mmap_limit_;
};

// Return the maximum number of concurrent mmaps.
static int MaxMmaps() {
  if (mmap_limit >= 0) {
    return mmap_limit;
  }
  // Up to 1000 mmaps for 64-bit binaries; none for smaller pointer sizes.
  mmap_limit = sizeof(void*) >= 8 ? 1000 : 0;
  return mmap_limit;
}

WindowsEnv::WindowsEnv() : started_bgthread_(false), mmap_limit_(MaxMmaps()) {}

void WindowsEnv::Schedule(void (*function)(void*), void* arg) {
  std::lock_guard<std::mutex> guard(mu_);

  // Start background thread if necessary
  if (!started_bgthread_) {
    started_bgthread_ = true;
    std::thread t(&WindowsEnv::BGThread, this);
    t.detach();
  }

  // If the queue is currently empty, the background thread may currently be
  // waiting.
  if (queue_.empty()) {
    bgsignal_.notify_one();
  }

  // Add to priority queue
  queue_.push_back(BGItem());
  queue_.back().function = function;
  queue_.back().arg = arg;
}

void WindowsEnv::BGThread() {
  while (true) {
    // Wait until there is an item that is ready to run
    std::unique_lock<std::mutex> lk(mu_);
    bgsignal_.wait(lk, [this] { return !queue_.empty(); });

    void (*function)(void*) = queue_.front().function;
    void* arg = queue_.front().arg;
    queue_.pop_front();

    lk.unlock();
    (*function)(arg);
  }
}

}  // namespace

static std::once_flag once;
static Env* default_env;
static void InitDefaultEnv() { default_env = new WindowsEnv(); }

void EnvWindowsTestHelper::SetReadOnlyMMapLimit(int limit) {
  assert(default_env == nullptr);
  mmap_limit = limit;
}

Env* Env::Default() {
  std::call_once(once, InitDefaultEnv);
  return default_env;
}

}  // namespace leveldb
