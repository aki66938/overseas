import Foundation
import Darwin

struct TransportFailure: Error {
  let sent: Int
  var code: String { sent == 0 ? "pre_dispatch" : "uncertain" }
}

// Fixed local protocol. Only request identities and the four approved actions
// cross the Flutter channel. Socket operations run on the bridge worker queue.
enum AccessTransport {
  static let path = "/var/run/regen-access/control.sock"
  static func timeout(_ action: String) -> Double {
    switch action { case "connect": return 125; case "disconnect": return 95; case "probe": return 7; default: return 5 }
  }
  static func validRequest(_ args: [String: Any]) -> Bool {
    guard Set(args.keys) == Set(["id", "action"]), let id = args["id"] as? String,
          let action = args["action"] as? String,
          ["connect", "disconnect", "status", "probe"].contains(action) else { return false }
    return !id.isEmpty && id.utf8.count <= 64 && id.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
    }
  }
  static func validFrame(_ data: Data) -> Bool {
    data.count <= 65536 && data.last == 10 && data.filter { $0 == 10 }.count == 1 && String(data: data, encoding: .utf8) != nil
  }
  static func authenticated(uid: uid_t) -> Bool { uid == 0 }

  static func checkPaths() -> Bool {
    // /var is a standard OS symlink; validate its canonical target and every
    // writable boundary explicitly instead of following caller-selected paths.
    // Foundation may abbreviate /private/var back to /var after resolution.
    // POSIX realpath returns the actual filesystem target without that rewrite.
    guard let resolved = realpath(path, nil) else { return false }
    defer { free(resolved) }
    guard String(cString: resolved) == "/private/var/run/regen-access/control.sock" else { return false }
    for dir in ["/private", "/private/var", "/private/var/run", "/private/var/run/regen-access"] {
      var value = stat()
      guard lstat(dir, &value) == 0, value.st_uid == 0,
            value.st_mode & S_IFMT == S_IFDIR else { return false }
      let trustedRuntime = dir == "/private/var/run" && value.st_gid == 1 && value.st_mode & 0o777 == 0o775
      guard value.st_mode & 0o022 == 0 || trustedRuntime else { return false }
      if dir.hasSuffix("regen-access") && (value.st_gid != 0 || value.st_mode & 0o777 != 0o755) { return false }
    }
    var value = stat()
    return lstat(path, &value) == 0 && value.st_mode & S_IFMT == S_IFSOCK && value.st_mode & 0o777 == 0o600 && value.st_gid == 0 && value.st_uid == getuid()
  }

  static func wait(_ fd: Int32, _ events: Int16, until: TimeInterval, sent: Int) throws {
    while true {
      let remaining = until - ProcessInfo.processInfo.systemUptime
      guard remaining > 0 else { throw TransportFailure(sent: sent) }
      var item = pollfd(fd: fd, events: events, revents: 0)
      let result = poll(&item, 1, Int32(min(remaining * 1000 + 1, Double(Int32.max))))
      if result > 0 { return }
      if result < 0 && errno == EINTR { continue }
      throw TransportFailure(sent: sent)
    }
  }

  static func exchange(_ fd: Int32, frame: Data, deadline: TimeInterval) throws -> String {
    var sent = 0
    while sent < frame.count {
      try wait(fd, Int16(POLLOUT), until: deadline, sent: sent)
      let n = frame.withUnsafeBytes { bytes in Darwin.send(fd, bytes.baseAddress!.advanced(by: sent), frame.count - sent, 0) }
      if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
      guard n > 0 else { throw TransportFailure(sent: sent) }
      sent += n
    }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while data.count < 65536 {
      try wait(fd, Int16(POLLIN), until: deadline, sent: sent)
      let n = recv(fd, &buffer, min(buffer.count, 65537 - data.count), 0)
      if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
      guard n > 0 else { throw TransportFailure(sent: sent) }
      data.append(contentsOf: buffer.prefix(n))
      if data.contains(10) {
        guard validFrame(data), let result = String(data: data, encoding: .utf8) else { throw TransportFailure(sent: sent) }
        return result
      }
    }
    throw TransportFailure(sent: sent)
  }

  static func request(_ args: [String: Any]) throws -> String {
    guard validRequest(args), checkPaths() else { throw TransportFailure(sent: 0) }
    let action = args["action"] as! String
    let deadline = ProcessInfo.processInfo.systemUptime + timeout(action)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw TransportFailure(sent: 0) }
    defer { close(fd) }
    guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw TransportFailure(sent: 0) }
    var enabled: Int32 = 1
    guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw TransportFailure(sent: 0) }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8) + [0]
    withUnsafeMutableBytes(of: &address.sun_path) { destination in destination.copyBytes(from: bytes) }
    let result = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    if result != 0 {
      guard errno == EINPROGRESS else { throw TransportFailure(sent: 0) }
      try wait(fd, Int16(POLLOUT), until: deadline, sent: 0)
      var error: Int32 = 0
      var length = socklen_t(MemoryLayout<Int32>.size)
      guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0 else { throw TransportFailure(sent: 0) }
    }
    var uid: uid_t = 0, gid: gid_t = 0
    guard getpeereid(fd, &uid, &gid) == 0, authenticated(uid: uid) else { throw TransportFailure(sent: 0) }
    var frame = try JSONSerialization.data(withJSONObject: ["version": 1, "id": args["id"]!, "action": action])
    frame.append(10)
    return try exchange(fd, frame: frame, deadline: deadline)
  }
}
