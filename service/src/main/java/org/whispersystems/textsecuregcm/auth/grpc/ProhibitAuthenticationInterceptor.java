/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.auth.grpc;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;

/**
 * A "prohibit authentication" interceptor ensures that requests to endpoints that should be invoked anonymously do not
 * contain an authorization header in the request metdata. Calls with an associated authenticated device are closed with
 * an {@code UNAUTHENTICATED} status.
 */
public class ProhibitAuthenticationInterceptor implements ServerInterceptor {

  @Override
  public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(final ServerCall<ReqT, RespT> call,
      final Metadata headers, final ServerCallHandler<ReqT, RespT> next) {
    final String authHeaderString = headers.get(Metadata.Key.of(RequireAuthenticationInterceptor.AUTHORIZATION_HEADER, Metadata.ASCII_STRING_MARSHALLER));
    if (authHeaderString != null) {
      call.close(Status.UNAUTHENTICATED.withDescription("authorization header forbidden"), new Metadata());
      return new ServerCall.Listener<>() {};
    }
    return next.startCall(call, headers);
  }
}
