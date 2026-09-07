import '../model/status.dart';

abstract interface class AccessClient {
  Future<Status> status();
  Future<void> connect();
  Future<void> disconnect();
  Future<List<ProbeResult>> probe();
}

/// Task 7 supplies the native APIv1 transport. Never emulate a live service.
class UnavailableAccessClient implements AccessClient {
  const UnavailableAccessClient();
  @override
  Future<Status> status() => Future.error(StateError('service unavailable'));
  @override
  Future<void> connect() => Future.error(StateError('service unavailable'));
  @override
  Future<void> disconnect() => Future.error(StateError('service unavailable'));
  @override
  Future<List<ProbeResult>> probe() =>
      Future.error(StateError('service unavailable'));
}
