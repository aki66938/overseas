import '../model/status.dart';

abstract interface class AccessClient {
  Future<Status> status();
  /// Complete only after the service operation ends or cancellation is confirmed.
  /// A local timeout must not release ownership of a still-running operation.
  Future<void> connect();
  /// Same completion/confirmed-cancellation contract as [connect].
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
