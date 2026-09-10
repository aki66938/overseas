import Foundation
import Darwin

// Standalone native test: swiftc Runner/AccessTransport.swift RunnerTests/TransportTests.swift -o transport-tests
@main struct TransportTests {
  static func main() throws {
    assert(AccessTransport.timeout("connect") == 125)
    assert(AccessTransport.timeout("disconnect") == 95)
    assert(AccessTransport.timeout("status") == 5)
    assert(AccessTransport.validRequest(["id": "abc", "action": "status"]))
    assert(!AccessTransport.validRequest(["id": "abc", "action": "diagnostic-enable"]))
    assert(!AccessTransport.validRequest(["id": "abc", "action": "status", "path": "/tmp/socket"]))
    assert(AccessTransport.validFrame(Data("{}\n".utf8)))
    assert(!AccessTransport.validFrame(Data("{}\n{}\n".utf8)))
    assert(!AccessTransport.validFrame(Data("{}".utf8)))
    assert(!AccessTransport.validFrame(Data(repeating: 65, count: 65537)))
    assert(AccessTransport.authenticated(uid: 0))
    assert(!AccessTransport.authenticated(uid: 501))
    assert(TransportFailure(sent: 0).code == "pre_dispatch")
    assert(TransportFailure(sent: 1).code == "uncertain")
    for reply in ["{}\n", "{}\n{}\n", "truncated"] {
      var pair: [Int32] = [0, 0]
      precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
      let client = pair[0], server = pair[1]
      DispatchQueue.global().async {
        var request = [UInt8](repeating: 0, count: 32)
        _ = recv(server, &request, request.count, 0)
        _ = reply.withCString { send(server, $0, reply.utf8.count, 0) }
        close(server)
      }
      do {
        let result = try AccessTransport.exchange(client, frame: Data("request\n".utf8), deadline: ProcessInfo.processInfo.systemUptime + 1)
        assert(reply == "{}\n" && result == reply)
      } catch let failure as TransportFailure {
        assert(reply != "{}\n" && failure.code == "uncertain")
      }
      close(client)
    }
    var pair: [Int32] = [0, 0]
    precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
    var actualUID: uid_t = 0, actualGID: gid_t = 0
    precondition(getpeereid(pair[0], &actualUID, &actualGID) == 0)
    assert(actualUID == getuid())
    assert(AccessTransport.authenticated(uid: actualUID) == (getuid() == 0))
    do {
      _ = try AccessTransport.exchange(pair[0], frame: Data("request\n".utf8), deadline: ProcessInfo.processInfo.systemUptime + 0.03)
      assertionFailure("missing action timeout")
    } catch let failure as TransportFailure { assert(failure.code == "uncertain") }
    close(pair[0]); close(pair[1])
    print("native transport validation passed")
  }
}
