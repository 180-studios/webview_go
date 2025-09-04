/*
 * MIT License
 *
 * Copyright (c) 2017 Serge Zaitsev
 * Copyright (c) 2022 Steffen André Langnes
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/// @file webview.h

#ifndef WEBVIEW_H
#define WEBVIEW_H

/**
 * Used to specify function linkage such as extern, inline, etc.
 *
 * When @c WEBVIEW_API is not already defined, the defaults are as follows:
 *
 * - @c inline when compiling C++ code.
 * - @c extern when compiling C code.
 *
 * The following macros can be used to automatically set an appropriate
 * value for @c WEBVIEW_API:
 *
 * - Define @c WEBVIEW_BUILD_SHARED when building a shared library.
 * - Define @c WEBVIEW_SHARED when using a shared library.
 * - Define @c WEBVIEW_STATIC when building or using a static library.
 */
#ifndef WEBVIEW_API
  #if defined(WEBVIEW_SHARED) || defined(WEBVIEW_BUILD_SHARED)
    #define WEBVIEW_API __attribute__((visibility("default")))
  #elif !defined(WEBVIEW_STATIC) && defined(__cplusplus)
    #define WEBVIEW_API inline
  #else
    #define WEBVIEW_API extern
  #endif
#endif

/// @name Version
/// @{

#ifndef WEBVIEW_VERSION_MAJOR
/// The current library major version.
#define WEBVIEW_VERSION_MAJOR 0
#endif

#ifndef WEBVIEW_VERSION_MINOR
/// The current library minor version.
#define WEBVIEW_VERSION_MINOR 11
#endif

#ifndef WEBVIEW_VERSION_PATCH
/// The current library patch version.
#define WEBVIEW_VERSION_PATCH 0
#endif

#ifndef WEBVIEW_VERSION_PRE_RELEASE
/// SemVer 2.0.0 pre-release labels prefixed with "-".
#define WEBVIEW_VERSION_PRE_RELEASE ""
#endif

#ifndef WEBVIEW_VERSION_BUILD_METADATA
/// SemVer 2.0.0 build metadata prefixed with "+".
#define WEBVIEW_VERSION_BUILD_METADATA ""
#endif

/// @}

/// @name Used internally
/// @{

/// Utility macro for stringifying a macro argument.
#define WEBVIEW_STRINGIFY(x) #x

/// Utility macro for stringifying the result of a macro argument expansion.
#define WEBVIEW_EXPAND_AND_STRINGIFY(x) WEBVIEW_STRINGIFY(x)

/// @}

/// @name Version
/// @{

/// SemVer 2.0.0 version number in MAJOR.MINOR.PATCH format.
#define WEBVIEW_VERSION_NUMBER                                                 \
  WEBVIEW_EXPAND_AND_STRINGIFY(WEBVIEW_VERSION_MAJOR)                          \
  "." WEBVIEW_EXPAND_AND_STRINGIFY(                                            \
      WEBVIEW_VERSION_MINOR) "." WEBVIEW_EXPAND_AND_STRINGIFY(WEBVIEW_VERSION_PATCH)

/// @}

/// Holds the elements of a MAJOR.MINOR.PATCH version number.
typedef struct {
  /// Major version.
  unsigned int major;
  /// Minor version.
  unsigned int minor;
  /// Patch version.
  unsigned int patch;
} webview_version_t;

/// Holds the library's version information.
typedef struct {
  /// The elements of the version number.
  webview_version_t version;
  /// SemVer 2.0.0 version number in MAJOR.MINOR.PATCH format.
  char version_number[32];
  /// SemVer 2.0.0 pre-release labels prefixed with "-" if specified, otherwise
  /// an empty string.
  char pre_release[48];
  /// SemVer 2.0.0 build metadata prefixed with "+", otherwise an empty string.
  char build_metadata[48];
} webview_version_info_t;

/// Pointer to a webview instance.
typedef void *webview_t;

/// Native handle kind. The actual type depends on the backend.
typedef enum {
  /// Top-level window. @c GtkWindow pointer (GTK)
  WEBVIEW_NATIVE_HANDLE_KIND_UI_WINDOW,
  /// Browser widget. @c GtkWidget pointer (GTK)
  WEBVIEW_NATIVE_HANDLE_KIND_UI_WIDGET,
  /// Browser controller. @c WebKitWebView pointer (WebKitGTK)
  WEBVIEW_NATIVE_HANDLE_KIND_BROWSER_CONTROLLER
} webview_native_handle_kind_t;

/// Window size hints
typedef enum {
  /// Width and height are default size.
  WEBVIEW_HINT_NONE,
  /// Width and height are minimum bounds.
  WEBVIEW_HINT_MIN,
  /// Width and height are maximum bounds.
  WEBVIEW_HINT_MAX,
  /// Window size can not be changed by a user.
  WEBVIEW_HINT_FIXED
} webview_hint_t;

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/**
 * Creates a new webview instance.
 *
 * @param debug Enable developer tools if supported by the backend.
 * @param window Optional native window handle, i.e. @c GtkWindow pointer
 *        If non-null, the webview widget is embedded into the given window,
 *        and the caller is expected to assume responsibility for the window as
 *        well as application lifecycle. If the window handle is null,
 *        a new window is created and both the window and application
 *        lifecycle are managed by the webview instance.
 * @return @c NULL on failure. Creation can fail for various reasons such
 *         as when required runtime dependencies are missing or when window
 *         creation fails.
 */
WEBVIEW_API webview_t webview_create(int debug, void *window);

/**
 * Destroys a webview instance and closes the native window.
 *
 * @param w The webview instance.
 */
WEBVIEW_API void webview_destroy(webview_t w);

/**
 * Runs the main loop until it's terminated.
 *
 * @param w The webview instance.
 */
WEBVIEW_API void webview_run(webview_t w);

/**
 * Stops the main loop. It is safe to call this function from another other
 * background thread.
 *
 * @param w The webview instance.
 */
WEBVIEW_API void webview_terminate(webview_t w);

/**
 * Schedules a function to be invoked on the thread with the run/event loop.
 * Use this function e.g. to interact with the library or native handles.
 *
 * @param w The webview instance.
 * @param fn The function to be invoked.
 * @param arg An optional argument passed along to the callback function.
 */
WEBVIEW_API void
webview_dispatch(webview_t w, void (*fn)(webview_t w, void *arg), void *arg);

/**
 * Returns the native handle of the window associated with the webview instance.
 * The handle can be a @c GtkWindow pointer (GTK)
 *
 * @param w The webview instance.
 * @return The handle of the native window.
 */
WEBVIEW_API void *webview_get_window(webview_t w);

/**
 * Get a native handle of choice.
 *
 * @param w The webview instance.
 * @param kind The kind of handle to retrieve.
 * @return The native handle or @c NULL.
 * @since 0.11
 */
WEBVIEW_API void *webview_get_native_handle(webview_t w,
                                            webview_native_handle_kind_t kind);

/**
 * Updates the title of the native window.
 *
 * @param w The webview instance.
 * @param title The new title.
 */
WEBVIEW_API void webview_set_title(webview_t w, const char *title);

/**
 * Updates the size of the native window.
 *
 * @param w The webview instance.
 * @param width New width.
 * @param height New height.
 * @param hints Size hints.
 */
WEBVIEW_API void webview_set_size(webview_t w, int width, int height,
                                  webview_hint_t hints);

/**
 * Navigates webview to the given URL. URL may be a properly encoded data URI.
 *
 * Example:
 * @code{.c}
 * webview_navigate(w, "https://github.com/webview/webview");
 * webview_navigate(w, "data:text/html,%3Ch1%3EHello%3C%2Fh1%3E");
 * webview_navigate(w, "data:text/html;base64,PGgxPkhlbGxvPC9oMT4=");
 * @endcode
 *
 * @param w The webview instance.
 * @param url URL.
 */
WEBVIEW_API void webview_navigate(webview_t w, const char *url);

/**
 * Load HTML content into the webview.
 *
 * Example:
 * @code{.c}
 * webview_set_html(w, "<h1>Hello</h1>");
 * @endcode
 *
 * @param w The webview instance.
 * @param html HTML content.
 */
WEBVIEW_API void webview_set_html(webview_t w, const char *html);

/**
 * Injects JavaScript code to be executed immediately upon loading a page.
 * The code will be executed before @c window.onload.
 *
 * @param w The webview instance.
 * @param js JS content.
 */
WEBVIEW_API void webview_init(webview_t w, const char *js);

/**
 * Evaluates arbitrary JavaScript code.
 *
 * Use bindings if you need to communicate the result of the evaluation.
 *
 * @param w The webview instance.
 * @param js JS content.
 */
WEBVIEW_API void webview_eval(webview_t w, const char *js);

/**
 * Binds a function pointer to a new global JavaScript function.
 *
 * Internally, JS glue code is injected to create the JS function by the
 * given name. The callback function is passed a sequential request
 * identifier, a request string and a user-provided argument. The request
 * string is a JSON array of the arguments passed to the JS function.
 *
 * @param w The webview instance.
 * @param name Name of the JS function.
 * @param fn Callback function.
 * @param arg User argument.
 */
WEBVIEW_API void webview_bind(webview_t w, const char *name,
                              void (*fn)(const char *seq, const char *req,
                                         void *arg),
                              void *arg);

/**
 * Removes a binding created with webview_bind().
 *
 * @param w The webview instance.
 * @param name Name of the binding.
 */
WEBVIEW_API void webview_unbind(webview_t w, const char *name);

/**
 * Responds to a binding call from the JS side.
 *
 * @param w The webview instance.
 * @param seq The sequence number of the binding call. Pass along the value
 *            received in the binding handler (see webview_bind()).
 * @param status A status of zero tells the JS side that the binding call was
 *               succesful; any other value indicates an error.
 * @param result The result of the binding call to be returned to the JS side.
 *               This must either be a valid JSON value or an empty string for
 *               the primitive JS value @c undefined.
 */
WEBVIEW_API void webview_return(webview_t w, const char *seq, int status,
                                const char *result);

/**
 * Registers a custom URI scheme handler.
 *
 * @param w The webview instance.
 * @param scheme The URI scheme to register (e.g., "myapp").
 * @param index The callback index for the Go handler.
 * @return 1 on success, 0 on failure.
 */
WEBVIEW_API int webview_register_uri_scheme(webview_t w, const char *scheme, unsigned long index);

/**
 * Unregisters a custom URI scheme handler.
 *
 * @param w The webview instance.
 * @param scheme The URI scheme to unregister.
 * @return 1 on success, 0 on failure.
 */
WEBVIEW_API int webview_unregister_uri_scheme(webview_t w, const char *scheme);

/**
 * Responds to a URI scheme request from the Go side.
 *
 * @param w The webview instance.
 * @param request The WebKit URI scheme request.
 * @param status HTTP status code (200 for success, 404 for not found, etc.).
 * @param content_type MIME type of the response.
 * @param data Response data.
 * @param data_length Length of the response data.
 */
WEBVIEW_API void webview_uri_scheme_response(webview_t w, unsigned long request_id, int status,
                                           const char *content_type, const char *data, size_t data_length);

/**
 * Get the library's version information.
 *
 * @since 0.10
 */
WEBVIEW_API const webview_version_info_t *webview_version(void);

#ifdef __cplusplus
}

#ifndef WEBVIEW_HEADER

#ifndef WEBVIEW_DEPRECATED
#if __cplusplus >= 201402L
#define WEBVIEW_DEPRECATED(reason) [[deprecated(reason)]]
#else
#define WEBVIEW_DEPRECATED(reason) __attribute__((deprecated(reason)))
#endif
#endif

#ifndef WEBVIEW_DEPRECATED_PRIVATE
#define WEBVIEW_DEPRECATED_PRIVATE                                             \
  WEBVIEW_DEPRECATED("Private API should not be used")
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <cstring>

#include <dlfcn.h>

namespace webview {

using dispatch_fn_t = std::function<void()>;

namespace detail {

// The library's version information.
constexpr const webview_version_info_t library_version_info{
    {WEBVIEW_VERSION_MAJOR, WEBVIEW_VERSION_MINOR, WEBVIEW_VERSION_PATCH},
    WEBVIEW_VERSION_NUMBER,
    WEBVIEW_VERSION_PRE_RELEASE,
    WEBVIEW_VERSION_BUILD_METADATA};

inline int json_parse_c(const char *s, size_t sz, const char *key, size_t keysz,
                        const char **value, size_t *valuesz) {
  enum {
    JSON_STATE_VALUE,
    JSON_STATE_LITERAL,
    JSON_STATE_STRING,
    JSON_STATE_ESCAPE,
    JSON_STATE_UTF8
  } state = JSON_STATE_VALUE;
  const char *k = nullptr;
  int index = 1;
  int depth = 0;
  int utf8_bytes = 0;

  *value = nullptr;
  *valuesz = 0;

  if (key == nullptr) {
    index = static_cast<decltype(index)>(keysz);
    if (index < 0) {
      return -1;
    }
    keysz = 0;
  }

  for (; sz > 0; s++, sz--) {
    enum {
      JSON_ACTION_NONE,
      JSON_ACTION_START,
      JSON_ACTION_END,
      JSON_ACTION_START_STRUCT,
      JSON_ACTION_END_STRUCT
    } action = JSON_ACTION_NONE;
    auto c = static_cast<unsigned char>(*s);
    switch (state) {
    case JSON_STATE_VALUE:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ':') {
        continue;
      } else if (c == '"') {
        action = JSON_ACTION_START;
        state = JSON_STATE_STRING;
      } else if (c == '{' || c == '[') {
        action = JSON_ACTION_START_STRUCT;
      } else if (c == '}' || c == ']') {
        action = JSON_ACTION_END_STRUCT;
      } else if (c == 't' || c == 'f' || c == 'n' || c == '-' ||
                 (c >= '0' && c <= '9')) {
        action = JSON_ACTION_START;
        state = JSON_STATE_LITERAL;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_LITERAL:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ']' || c == '}' || c == ':') {
        state = JSON_STATE_VALUE;
        s--;
        sz++;
        action = JSON_ACTION_END;
      } else if (c < 32 || c > 126) {
        return -1;
      } // fallthrough
    case JSON_STATE_STRING:
      if (c < 32 || (c > 126 && c < 192)) {
        return -1;
      } else if (c == '"') {
        action = JSON_ACTION_END;
        state = JSON_STATE_VALUE;
      } else if (c == '\\') {
        state = JSON_STATE_ESCAPE;
      } else if (c >= 192 && c < 224) {
        utf8_bytes = 1;
        state = JSON_STATE_UTF8;
      } else if (c >= 224 && c < 240) {
        utf8_bytes = 2;
        state = JSON_STATE_UTF8;
      } else if (c >= 240 && c < 247) {
        utf8_bytes = 3;
        state = JSON_STATE_UTF8;
      } else if (c >= 128 && c < 192) {
        return -1;
      }
      break;
    case JSON_STATE_ESCAPE:
      if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
          c == 'n' || c == 'r' || c == 't' || c == 'u') {
        state = JSON_STATE_STRING;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_UTF8:
      if (c < 128 || c > 191) {
        return -1;
      }
      utf8_bytes--;
      if (utf8_bytes == 0) {
        state = JSON_STATE_STRING;
      }
      break;
    default:
      return -1;
    }

    if (action == JSON_ACTION_END_STRUCT) {
      depth--;
    }

    if (depth == 1) {
      if (action == JSON_ACTION_START || action == JSON_ACTION_START_STRUCT) {
        if (index == 0) {
          *value = s;
        } else if (keysz > 0 && index == 1) {
          k = s;
        } else {
          index--;
        }
      } else if (action == JSON_ACTION_END ||
                 action == JSON_ACTION_END_STRUCT) {
        if (*value != nullptr && index == 0) {
          *valuesz = (size_t)(s + 1 - *value);
          return 0;
        } else if (keysz > 0 && k != nullptr) {
          if (keysz == (size_t)(s - k - 1) && memcmp(key, k + 1, keysz) == 0) {
            index = 0;
          } else {
            index = 2;
          }
          k = nullptr;
        }
      }
    }

    if (action == JSON_ACTION_START_STRUCT) {
      depth++;
    }
  }
  return -1;
}

constexpr bool is_json_special_char(char c) {
  return c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' ||
         c == '\r' || c == '\t';
}

constexpr bool is_ascii_control_char(char c) { return c >= 0 && c <= 0x1f; }

inline std::string json_escape(const std::string &s, bool add_quotes = true) {
  // Calculate the size of the resulting string.
  // Add space for the double quotes.
  size_t required_length = add_quotes ? 2 : 0;
  for (auto c : s) {
    if (is_json_special_char(c)) {
      // '\' and a single following character
      required_length += 2;
      continue;
    }
    if (is_ascii_control_char(c)) {
      // '\', 'u', 4 digits
      required_length += 6;
      continue;
    }
    ++required_length;
  }
  // Allocate memory for resulting string only once.
  std::string result;
  result.reserve(required_length);
  if (add_quotes) {
    result += '"';
  }
  // Copy string while escaping characters.
  for (auto c : s) {
    if (is_json_special_char(c)) {
      static constexpr char special_escape_table[256] =
          "\0\0\0\0\0\0\0\0btn\0fr\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\"\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\\";
      result += '\\';
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      result += special_escape_table[static_cast<unsigned char>(c)];
      continue;
    }
    if (is_ascii_control_char(c)) {
      // Escape as \u00xx
      static constexpr char hex_alphabet[]{"0123456789abcdef"};
      auto uc = static_cast<unsigned char>(c);
      auto h = (uc >> 4) & 0x0f;
      auto l = uc & 0x0f;
      result += "\\u00";
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
      result += hex_alphabet[h];
      result += hex_alphabet[l];
      // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
      continue;
    }
    result += c;
  }
  if (add_quotes) {
    result += '"';
  }
  // Should have calculated the exact amount of memory needed
  assert(required_length == result.size());
  return result;
}

inline int json_unescape(const char *s, size_t n, char *out) {
  int r = 0;
  if (*s++ != '"') {
    return -1;
  }
  while (n > 2) {
    char c = *s;
    if (c == '\\') {
      s++;
      n--;
      switch (*s) {
      case 'b':
        c = '\b';
        break;
      case 'f':
        c = '\f';
        break;
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      case '\\':
        c = '\\';
        break;
      case '/':
        c = '/';
        break;
      case '\"':
        c = '\"';
        break;
      default: // TODO: support unicode decoding
        return -1;
      }
    }
    if (out != nullptr) {
      *out++ = c;
    }
    s++;
    n--;
    r++;
  }
  if (*s != '"') {
    return -1;
  }
  if (out != nullptr) {
    *out = '\0';
  }
  return r;
}

inline std::string json_parse(const std::string &s, const std::string &key,
                              const int index) {
  const char *value;
  size_t value_sz;
  if (key.empty()) {
    json_parse_c(s.c_str(), s.length(), nullptr, index, &value, &value_sz);
  } else {
    json_parse_c(s.c_str(), s.length(), key.c_str(), key.length(), &value,
                 &value_sz);
  }
  if (value != nullptr) {
    if (value[0] != '"') {
      return {value, value_sz};
    }
    int n = json_unescape(value, value_sz, nullptr);
    if (n > 0) {
      char *decoded = new char[n + 1];
      json_unescape(value, value_sz, decoded);
      std::string result(decoded, n);
      delete[] decoded;
      return result;
    }
  }
  return "";
}

// Holds a symbol name and associated type for code clarity.
template <typename T> class library_symbol {
public:
  using type = T;

  constexpr explicit library_symbol(const char *name) : m_name(name) {}
  constexpr const char *get_name() const { return m_name; }

private:
  const char *m_name;
};

// Loads a native shared library and allows one to get addresses for those
// symbols.
class native_library {
public:
  native_library() = default;

  explicit native_library(const std::string &name)
      : m_handle{load_library(name)} {}

  ~native_library() {
    if (m_handle) {
      dlclose(m_handle);
      m_handle = nullptr;
    }
  }

  native_library(const native_library &other) = delete;
  native_library &operator=(const native_library &other) = delete;
  native_library(native_library &&other) noexcept { *this = std::move(other); }

  native_library &operator=(native_library &&other) noexcept {
    if (this == &other) {
      return *this;
    }
    m_handle = other.m_handle;
    other.m_handle = nullptr;
    return *this;
  }

  // Returns true if the library is currently loaded; otherwise false.
  operator bool() const { return is_loaded(); }

  // Get the address for the specified symbol or nullptr if not found.
  template <typename Symbol>
  typename Symbol::type get(const Symbol &symbol) const {
    if (is_loaded()) {
      // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
      return reinterpret_cast<typename Symbol::type>(
          dlsym(m_handle, symbol.get_name()));
      // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    return nullptr;
  }

  // Returns true if the library is currently loaded; otherwise false.
  bool is_loaded() const { return !!m_handle; }

  void detach() { m_handle = nullptr; }

  // Returns true if the library by the given name is currently loaded; otherwise false.
  static inline bool is_loaded(const std::string &name) {
    auto handle = dlopen(name.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
      dlclose(handle);
    }
    return !!handle;
  }

private:
  using mod_handle_t = void *;

  static inline mod_handle_t load_library(const std::string &name) {
    return dlopen(name.c_str(), RTLD_NOW);
  }

  mod_handle_t m_handle{};
};

class engine_base {
public:
  virtual ~engine_base() = default;

  void navigate(const std::string &url) {
    if (url.empty()) {
      navigate_impl("about:blank");
      return;
    }
    navigate_impl(url);
  }

  using binding_t = std::function<void(std::string, std::string, void *)>;
  class binding_ctx_t {
  public:
    binding_ctx_t(binding_t callback, void *arg)
        : callback(callback), arg(arg) {}
    // This function is called upon execution of the bound JS function
    binding_t callback;
    // This user-supplied argument is passed to the callback
    void *arg;
  };

  using sync_binding_t = std::function<std::string(std::string)>;

  // Synchronous bind
  void bind(const std::string &name, sync_binding_t fn) {
    auto wrapper = [this, fn](const std::string &seq, const std::string &req,
                              void * /*arg*/) { resolve(seq, 0, fn(req)); };
    bind(name, wrapper, nullptr);
  }

  // Asynchronous bind
  void bind(const std::string &name, binding_t fn, void *arg) {
    // NOLINTNEXTLINE(readability-container-contains): contains() requires C++20
    if (bindings.count(name) > 0) {
      return;
    }
    bindings.emplace(name, binding_ctx_t(fn, arg));
    auto js = "(function() { var name = '" + name + "';" + R""(
      var RPC = window._rpc = (window._rpc || {nextSeq: 1});
      window[name] = function() {
        var seq = RPC.nextSeq++;
        var promise = new Promise(function(resolve, reject) {
          RPC[seq] = {
            resolve: resolve,
            reject: reject,
          };
        });
        window.external.invoke(JSON.stringify({
          id: seq,
          method: name,
          params: Array.prototype.slice.call(arguments),
        }));
        return promise;
      }
    })())"";
    init(js);
    eval(js);
  }

  void unbind(const std::string &name) {
    auto found = bindings.find(name);
    if (found != bindings.end()) {
      auto js = "delete window['" + name + "'];";
      init(js);
      eval(js);
      bindings.erase(found);
    }
  }

  void resolve(const std::string &seq, int status, const std::string &result) {
    // NOLINTNEXTLINE(modernize-avoid-bind): Lambda with move requires C++14
    dispatch(std::bind(
        [seq, status, this](std::string escaped_result) {
          std::string js;
          js += "(function(){var seq = \"";
          js += seq;
          js += "\";\n";
          js += "var status = ";
          js += std::to_string(status);
          js += ";\n";
          js += "var result = ";
          js += escaped_result;
          js += ";\
var promise = window._rpc[seq];\
delete window._rpc[seq];\
if (result !== undefined) {\
  try {\
    result = JSON.parse(result);\
  } catch {\
    promise.reject(new Error(\"Failed to parse binding result as JSON\"));\
    return;\
  }\
}\
if (status === 0) {\
  promise.resolve(result);\
} else {\
  promise.reject(result);\
}\
})()";
          eval(js);
        },
        result.empty() ? "undefined" : json_escape(result)));
  }

  void *window() { return window_impl(); }
  void *widget() { return widget_impl(); }
  void *browser_controller() { return browser_controller_impl(); };
  void run() { run_impl(); }
  void terminate() { terminate_impl(); }
  void dispatch(std::function<void()> f) { dispatch_impl(f); }
  void set_title(const std::string &title) { set_title_impl(title); }

  void set_size(int width, int height, webview_hint_t hints) {
    set_size_impl(width, height, hints);
  }

  void set_html(const std::string &html) { set_html_impl(html); }
  void init(const std::string &js) { init_impl(js); }
  void eval(const std::string &js) { eval_impl(js); }

protected:
  virtual void navigate_impl(const std::string &url) = 0;
  virtual void *window_impl() = 0;
  virtual void *widget_impl() = 0;
  virtual void *browser_controller_impl() = 0;
  virtual void run_impl() = 0;
  virtual void terminate_impl() = 0;
  virtual void dispatch_impl(std::function<void()> f) = 0;
  virtual void set_title_impl(const std::string &title) = 0;
  virtual void set_size_impl(int width, int height, webview_hint_t hints) = 0;
  virtual void set_html_impl(const std::string &html) = 0;
  virtual void init_impl(const std::string &js) = 0;
  virtual void eval_impl(const std::string &js) = 0;

  virtual void on_message(const std::string &msg) {
    auto seq = json_parse(msg, "id", 0);
    auto name = json_parse(msg, "method", 0);
    auto args = json_parse(msg, "params", 0);
    auto found = bindings.find(name);
    if (found == bindings.end()) {
      return;
    }
    const auto &context = found->second;
    context.callback(seq, args, context.arg);
  }

  virtual void on_window_created() { inc_window_count(); }

  virtual void on_window_destroyed(bool skip_termination = false) {
    if (dec_window_count() <= 0) {
      if (!skip_termination) {
        terminate();
      }
    }
  }

private:
  static std::atomic_uint &window_ref_count() {
    static std::atomic_uint ref_count{0};
    return ref_count;
  }

  static unsigned int inc_window_count() { return ++window_ref_count(); }

  static unsigned int dec_window_count() {
    auto &count = window_ref_count();
    if (count > 0) {
      return --count;
    }
    return 0;
  }

  std::map<std::string, binding_ctx_t> bindings;
};

} // namespace detail

WEBVIEW_DEPRECATED_PRIVATE
inline int json_parse_c(const char *s, size_t sz, const char *key, size_t keysz,
                        const char **value, size_t *valuesz) {
  return detail::json_parse_c(s, sz, key, keysz, value, valuesz);
}

WEBVIEW_DEPRECATED_PRIVATE
inline std::string json_escape(const std::string &s) {
  return detail::json_escape(s);
}

WEBVIEW_DEPRECATED_PRIVATE
inline int json_unescape(const char *s, size_t n, char *out) {
  return detail::json_unescape(s, n, out);
}

WEBVIEW_DEPRECATED_PRIVATE
inline std::string json_parse(const std::string &s, const std::string &key,
                              const int index) {
  return detail::json_parse(s, key, index);
}

} // namespace webview

#if defined(WEBVIEW_GTK)
//
// ====================================================================
//
// This implementation uses webkit2gtk backend. It requires gtk+3.0 and
// webkit2gtk-4.1 libraries. Proper compiler flags can be retrieved via:
//
//   pkg-config --cflags --libs gtk+-3.0 webkit2gtk-4.1
//
// ====================================================================
//
#include <cstdlib>

#include <JavaScriptCore/JavaScript.h>
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

#ifdef GDK_WINDOWING_X11
#include <gdk/gdkx.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>

namespace webview {
namespace detail {

// Namespace containing workaround for WebKit 2.42 when using NVIDIA GPU
// driver.
// See WebKit bug: https://bugs.webkit.org/show_bug.cgi?id=261874
// Please remove all of the code in this namespace when it's no longer needed.
namespace webkit_dmabuf {

// Get environment variable. Not thread-safe.
static inline std::string get_env(const std::string &name) {
  auto *value = std::getenv(name.c_str());
  if (value) {
    return {value};
  }
  return {};
}

// Set environment variable. Not thread-safe.
static inline void set_env(const std::string &name, const std::string &value) {
  ::setenv(name.c_str(), value.c_str(), 1);
}

// Checks whether the NVIDIA GPU driver is used based on whether the kernel
// module is loaded.
static inline bool is_using_nvidia_driver() {
  struct ::stat buffer {};
  if (::stat("/sys/module/nvidia", &buffer) != 0) {
    return false;
  }
  return S_ISDIR(buffer.st_mode);
}

// Checks whether the windowing system is Wayland.
static inline bool is_wayland_display() {
  if (!get_env("WAYLAND_DISPLAY").empty()) {
    return true;
  }
  if (get_env("XDG_SESSION_TYPE") == "wayland") {
    return true;
  }
  if (get_env("DESKTOP_SESSION").find("wayland") != std::string::npos) {
    return true;
  }
  return false;
}

// Checks whether the GDK X11 backend is used.
// See: https://docs.gtk.org/gdk3/class.DisplayManager.html
static inline bool is_gdk_x11_backend() {
#ifdef GDK_WINDOWING_X11
  auto *manager = gdk_display_manager_get();
  auto *display = gdk_display_manager_get_default_display(manager);
  return GDK_IS_X11_DISPLAY(display); // NOLINT(misc-const-correctness)
#else
  return false;
#endif
}

// Checks whether WebKit is affected by bug when using DMA-BUF renderer.
// Returns true if all of the following conditions are met:
//  - WebKit version is >= 2.42 (please narrow this down when there's a fix).
//  - Environment variables are empty or not set:
//    - WEBKIT_DISABLE_DMABUF_RENDERER
//  - Windowing system is not Wayland.
//  - GDK backend is X11.
//  - NVIDIA GPU driver is used.
static inline bool is_webkit_dmabuf_bugged() {
  auto wk_major = webkit_get_major_version();
  auto wk_minor = webkit_get_minor_version();
  // TODO: Narrow down affected WebKit version when there's a fixed version
  auto is_affected_wk_version = wk_major == 2 && wk_minor >= 42;
  if (!is_affected_wk_version) {
    return false;
  }
  if (!get_env("WEBKIT_DISABLE_DMABUF_RENDERER").empty()) {
    return false;
  }
  if (is_wayland_display()) {
    return false;
  }
  if (!is_gdk_x11_backend()) {
    return false;
  }
  if (!is_using_nvidia_driver()) {
    return false;
  }
  return true;
}

// Applies workaround for WebKit DMA-BUF bug if needed.
// See WebKit bug: https://bugs.webkit.org/show_bug.cgi?id=261874
static inline void apply_webkit_dmabuf_workaround() {
  if (!is_webkit_dmabuf_bugged()) {
    return;
  }
  set_env("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
}
} // namespace webkit_dmabuf

namespace webkit_symbols {
using webkit_web_view_evaluate_javascript_t =
    void (*)(WebKitWebView *, const char *, gssize, const char *, const char *,
             GCancellable *, GAsyncReadyCallback, gpointer);

using webkit_web_view_run_javascript_t = void (*)(WebKitWebView *,
                                                  const gchar *, GCancellable *,
                                                  GAsyncReadyCallback,
                                                  gpointer);

constexpr auto webkit_web_view_evaluate_javascript =
    library_symbol<webkit_web_view_evaluate_javascript_t>(
        "webkit_web_view_evaluate_javascript");
constexpr auto webkit_web_view_run_javascript =
    library_symbol<webkit_web_view_run_javascript_t>(
        "webkit_web_view_run_javascript");
} // namespace webkit_symbols

extern "C" {
void _webview_uri_scheme_cb(const char* uri, unsigned long request_id, void *arg, unsigned long index);
}

struct uri_scheme_context {
  unsigned long index;
  void* engine;
};

class gtk_webkit_engine : public engine_base {
public:
  gtk_webkit_engine(bool debug, void *window)
      : m_owns_window{!window}, m_window(static_cast<GtkWidget *>(window)) {
    if (m_owns_window) {
      if (gtk_init_check(nullptr, nullptr) == FALSE) {
        return;
      }
      m_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
      on_window_created();
      g_signal_connect(G_OBJECT(m_window), "destroy",
                       G_CALLBACK(+[](GtkWidget *, gpointer arg) {
                         auto *w = static_cast<gtk_webkit_engine *>(arg);
                         // Widget destroyed along with window.
                         w->m_webview = nullptr;
                         w->m_window = nullptr;
                         w->on_window_destroyed();
                       }),
                       this);
    }
    webkit_dmabuf::apply_webkit_dmabuf_workaround();
    // Initialize webview widget
    m_webview = webkit_web_view_new();
    WebKitUserContentManager *manager =
        webkit_web_view_get_user_content_manager(WEBKIT_WEB_VIEW(m_webview));
    g_signal_connect(manager, "script-message-received::external",
                     G_CALLBACK(+[](WebKitUserContentManager *,
                                    WebKitJavascriptResult *r, gpointer arg) {
                       auto *w = static_cast<gtk_webkit_engine *>(arg);
                       char *s = get_string_from_js_result(r);
                       w->on_message(s);
                       g_free(s);
                     }),
                     this);
    webkit_user_content_manager_register_script_message_handler(manager,
                                                                "external");
    init("window.external={invoke:function(s){window.webkit.messageHandlers."
         "external.postMessage(s);}}");

    gtk_container_add(GTK_CONTAINER(m_window), GTK_WIDGET(m_webview));
    gtk_widget_show(GTK_WIDGET(m_webview));

    WebKitSettings *settings =
        webkit_web_view_get_settings(WEBKIT_WEB_VIEW(m_webview));
    webkit_settings_set_javascript_can_access_clipboard(settings, true);
    if (debug) {
      webkit_settings_set_enable_write_console_messages_to_stdout(settings,
                                                                  true);
      webkit_settings_set_enable_developer_extras(settings, true);
    }

    if (m_owns_window) {
      gtk_widget_grab_focus(GTK_WIDGET(m_webview));
      gtk_widget_show_all(m_window);
    }
  }

  gtk_webkit_engine(const gtk_webkit_engine &) = delete;
  gtk_webkit_engine &operator=(const gtk_webkit_engine &) = delete;
  gtk_webkit_engine(gtk_webkit_engine &&) = delete;
  gtk_webkit_engine &operator=(gtk_webkit_engine &&) = delete;

  virtual ~gtk_webkit_engine() {
    if (m_webview) {
      gtk_widget_destroy(GTK_WIDGET(m_webview));
      m_webview = nullptr;
    }
    if (m_window) {
      if (m_owns_window) {
        // Disconnect handlers to avoid callbacks invoked during destruction.
        g_signal_handlers_disconnect_by_data(GTK_WINDOW(m_window), this);
        gtk_window_close(GTK_WINDOW(m_window));
        on_window_destroyed(true);
      }
      m_window = nullptr;
    }
    if (m_owns_window) {
      // Needed for the window to close immediately.
      deplete_run_loop_event_queue();
    }
  }

  void *window_impl() override { return (void *)m_window; }
  void *widget_impl() override { return (void *)m_webview; }
  void *browser_controller_impl() override { return (void *)m_webview; };
  void run_impl() override { gtk_main(); }
  void terminate_impl() override {
    dispatch_impl([] { gtk_main_quit(); });
  }
  void dispatch_impl(std::function<void()> f) override {
    g_idle_add_full(G_PRIORITY_HIGH_IDLE, (GSourceFunc)([](void *f) -> int {
                      (*static_cast<dispatch_fn_t *>(f))();
                      return G_SOURCE_REMOVE;
                    }),
                    new std::function<void()>(f),
                    [](void *f) { delete static_cast<dispatch_fn_t *>(f); });
  }

  void set_title_impl(const std::string &title) override {
    gtk_window_set_title(GTK_WINDOW(m_window), title.c_str());
  }

  void set_size_impl(int width, int height, webview_hint_t hints) override {
    gtk_window_set_resizable(GTK_WINDOW(m_window), hints != WEBVIEW_HINT_FIXED);
    if (hints == WEBVIEW_HINT_NONE) {
      gtk_window_resize(GTK_WINDOW(m_window), width, height);
    } else if (hints == WEBVIEW_HINT_FIXED) {
      gtk_widget_set_size_request(m_window, width, height);
    } else {
      GdkGeometry g;
      g.min_width = g.max_width = width;
      g.min_height = g.max_height = height;
      GdkWindowHints h =
          (hints == WEBVIEW_HINT_MIN ? GDK_HINT_MIN_SIZE : GDK_HINT_MAX_SIZE);
      // This defines either MIN_SIZE, or MAX_SIZE, but not both:
      gtk_window_set_geometry_hints(GTK_WINDOW(m_window), nullptr, &g, h);
    }
  }

  void navigate_impl(const std::string &url) override {
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(m_webview), url.c_str());
  }

  void set_html_impl(const std::string &html) override {
    webkit_web_view_load_html(WEBKIT_WEB_VIEW(m_webview), html.c_str(),
                              nullptr);
  }

  void init_impl(const std::string &js) override {
    WebKitUserContentManager *manager =
        webkit_web_view_get_user_content_manager(WEBKIT_WEB_VIEW(m_webview));
    webkit_user_content_manager_add_script(
        manager,
        webkit_user_script_new(js.c_str(), WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
                               WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START,
                               nullptr, nullptr));
  }

  void eval_impl(const std::string &js) override {
    auto &lib = get_webkit_library();
    auto wkmajor = webkit_get_major_version();
    auto wkminor = webkit_get_minor_version();
    if ((wkmajor == 2 && wkminor >= 40) || wkmajor > 2) {
      if (auto fn =
              lib.get(webkit_symbols::webkit_web_view_evaluate_javascript)) {
        fn(WEBKIT_WEB_VIEW(m_webview), js.c_str(),
           static_cast<gssize>(js.size()), nullptr, nullptr, nullptr, nullptr,
           nullptr);
      }
    } else if (auto fn =
                   lib.get(webkit_symbols::webkit_web_view_run_javascript)) {
      fn(WEBKIT_WEB_VIEW(m_webview), js.c_str(), nullptr, nullptr, nullptr);
    }
  }

  bool register_uri_scheme(const std::string& scheme, unsigned long index) {
    if (m_uri_schemes.count(scheme) > 0) {
      return false;
    }
    
    WebKitWebContext* context = webkit_web_view_get_context(WEBKIT_WEB_VIEW(m_webview));
    if (!context) {
      return false;
    }
    
    uri_scheme_context* ctx = new uri_scheme_context{index, this};
    m_uri_schemes[scheme] = ctx;
    
    webkit_web_context_register_uri_scheme(context, scheme.c_str(),
      [](WebKitURISchemeRequest* request, gpointer user_data) {
        auto* ctx = static_cast<uri_scheme_context*>(user_data);
        auto* engine = static_cast<gtk_webkit_engine*>(ctx->engine);
        engine->handle_uri_scheme_request(request, ctx->index);
      }, ctx, nullptr);
    
    return true;
  }

  bool unregister_uri_scheme(const std::string& scheme) {
    auto it = m_uri_schemes.find(scheme);
    if (it == m_uri_schemes.end()) {
      return false;
    }
    
    delete it->second;
    m_uri_schemes.erase(it);
    
    return true;
  }

  void uri_scheme_response(unsigned long request_id, int status, const char *content_type, const char *data, size_t data_length) {
    auto it = m_pending_requests.find(request_id);
    if (it == m_pending_requests.end()) {
      return;
    }
    
    WebKitURISchemeRequest* request = it->second;
    m_pending_requests.erase(it);
    
    GInputStream* stream = g_memory_input_stream_new_from_data(data, data_length, nullptr);
    
    WebKitURISchemeResponse* response = webkit_uri_scheme_response_new(stream, data_length);
    
    webkit_uri_scheme_response_set_status(response, status, nullptr);
    
    if (content_type && strlen(content_type) > 0) {
      webkit_uri_scheme_response_set_content_type(response, content_type);
    }
    
    webkit_uri_scheme_request_finish_with_response(request, response);
    
    g_object_unref(response);
    g_object_unref(stream);
  }

private:
  void handle_uri_scheme_request(WebKitURISchemeRequest* request, unsigned long index) {
    const char* uri = webkit_uri_scheme_request_get_uri(request);
    
    unsigned long request_id = m_next_request_id.fetch_add(1, std::memory_order_relaxed);
    m_pending_requests[request_id] = request;
    
    _webview_uri_scheme_cb(uri, request_id, static_cast<void*>(this), index);
  }

  static char *get_string_from_js_result(WebKitJavascriptResult *r) {
    char *s;
#if (WEBKIT_MAJOR_VERSION == 2 && WEBKIT_MINOR_VERSION >= 22) ||               \
    WEBKIT_MAJOR_VERSION > 2
    JSCValue *value = webkit_javascript_result_get_js_value(r);
    s = jsc_value_to_string(value);
#else
    JSGlobalContextRef ctx = webkit_javascript_result_get_global_context(r);
    JSValueRef value = webkit_javascript_result_get_value(r);
    JSStringRef js = JSValueToStringCopy(ctx, value, nullptr);
    size_t n = JSStringGetMaximumUTF8CStringSize(js);
    s = g_new(char, n);
    JSStringGetUTF8CString(js, s, n);
    JSStringRelease(js);
#endif
    return s;
  }

  static const native_library &get_webkit_library() {
    static const native_library non_loaded_lib;
    static native_library loaded_lib;

    if (loaded_lib.is_loaded()) {
      return loaded_lib;
    }

    constexpr std::array<const char *, 2> lib_names{"libwebkit2gtk-4.1.so",
                                                    "libwebkit2gtk-4.0.so"};
    auto found =
        std::find_if(lib_names.begin(), lib_names.end(), [](const char *name) {
          return native_library::is_loaded(name);
        });

    if (found == lib_names.end()) {
      return non_loaded_lib;
    }

    loaded_lib = native_library(*found);

    auto loaded = loaded_lib.is_loaded();
    if (!loaded) {
      return non_loaded_lib;
    }

    return loaded_lib;
  }

  // Blocks while depleting the run loop of events.
  void deplete_run_loop_event_queue() {
    bool done{};
    dispatch([&] { done = true; });
    while (!done) {
      gtk_main_iteration();
    }
  }

  bool m_owns_window{};
  GtkWidget *m_window{};
  GtkWidget *m_webview{};
  
  std::map<std::string, uri_scheme_context*> m_uri_schemes;
  std::map<unsigned long, WebKitURISchemeRequest*> m_pending_requests;
  std::atomic<unsigned long> m_next_request_id{1};
};

} // namespace detail

using browser_engine = detail::gtk_webkit_engine;

} // namespace webview

#endif /* WEBVIEW_GTK */

namespace webview {
using webview = browser_engine;
} // namespace webview

WEBVIEW_API webview_t webview_create(int debug, void *wnd) {
  auto w = new webview::webview(debug, wnd);
  if (!w->window()) {
    delete w;
    return nullptr;
  }
  return w;
}

WEBVIEW_API void webview_destroy(webview_t w) {
  delete static_cast<webview::webview *>(w);
}

WEBVIEW_API void webview_run(webview_t w) {
  static_cast<webview::webview *>(w)->run();
}

WEBVIEW_API void webview_terminate(webview_t w) {
  static_cast<webview::webview *>(w)->terminate();
}

WEBVIEW_API void webview_dispatch(webview_t w, void (*fn)(webview_t, void *),
                                  void *arg) {
  static_cast<webview::webview *>(w)->dispatch([=]() { fn(w, arg); });
}

WEBVIEW_API void *webview_get_window(webview_t w) {
  return static_cast<webview::webview *>(w)->window();
}

WEBVIEW_API void *webview_get_native_handle(webview_t w,
                                            webview_native_handle_kind_t kind) {
  auto *w_ = static_cast<webview::webview *>(w);
  switch (kind) {
  case WEBVIEW_NATIVE_HANDLE_KIND_UI_WINDOW:
    return w_->window();
  case WEBVIEW_NATIVE_HANDLE_KIND_UI_WIDGET:
    return w_->widget();
  case WEBVIEW_NATIVE_HANDLE_KIND_BROWSER_CONTROLLER:
    return w_->browser_controller();
  default:
    return nullptr;
  }
}

WEBVIEW_API void webview_set_title(webview_t w, const char *title) {
  static_cast<webview::webview *>(w)->set_title(title);
}

WEBVIEW_API void webview_set_size(webview_t w, int width, int height,
                                  webview_hint_t hints) {
  static_cast<webview::webview *>(w)->set_size(width, height, hints);
}

WEBVIEW_API void webview_navigate(webview_t w, const char *url) {
  static_cast<webview::webview *>(w)->navigate(url);
}

WEBVIEW_API void webview_set_html(webview_t w, const char *html) {
  static_cast<webview::webview *>(w)->set_html(html);
}

WEBVIEW_API void webview_init(webview_t w, const char *js) {
  static_cast<webview::webview *>(w)->init(js);
}

WEBVIEW_API void webview_eval(webview_t w, const char *js) {
  static_cast<webview::webview *>(w)->eval(js);
}

WEBVIEW_API void webview_bind(webview_t w, const char *name,
                              void (*fn)(const char *seq, const char *req,
                                         void *arg),
                              void *arg) {
  static_cast<webview::webview *>(w)->bind(
      name,
      [=](const std::string &seq, const std::string &req, void *arg) {
        fn(seq.c_str(), req.c_str(), arg);
      },
      arg);
}

WEBVIEW_API void webview_unbind(webview_t w, const char *name) {
  static_cast<webview::webview *>(w)->unbind(name);
}

WEBVIEW_API void webview_return(webview_t w, const char *seq, int status,
                                const char *result) {
  static_cast<webview::webview *>(w)->resolve(seq, status, result);
}

WEBVIEW_API const webview_version_info_t *webview_version(void) {
  return &webview::detail::library_version_info;
}

WEBVIEW_API int webview_register_uri_scheme(webview_t w, const char *scheme, unsigned long index) {
  auto *w_ = static_cast<webview::webview *>(w);
  return w_->register_uri_scheme(scheme, index) ? 1 : 0;
}

WEBVIEW_API int webview_unregister_uri_scheme(webview_t w, const char *scheme) {
  auto *w_ = static_cast<webview::webview *>(w);
  return w_->unregister_uri_scheme(scheme) ? 1 : 0;
}

WEBVIEW_API void webview_uri_scheme_response(webview_t w, unsigned long request_id, int status,
                                           const char *content_type, const char *data, size_t data_length) {
  auto *w_ = static_cast<webview::webview *>(w);
  w_->uri_scheme_response(request_id, status, content_type, data, data_length);
}

#endif /* WEBVIEW_HEADER */
#endif /* __cplusplus */
#endif /* WEBVIEW_H */
