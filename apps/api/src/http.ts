import type { FastifyReply, FastifyRequest } from "fastify";

export const sessionCookieName = "tv_session";

export function readCookie(request: FastifyRequest, name: string): string | undefined {
  const cookieHeader = request.headers.cookie;

  if (!cookieHeader) {
    return undefined;
  }

  return cookieHeader
    .split(";")
    .map((cookie) => cookie.trim())
    .map((cookie) => cookie.split("="))
    .find(([key]) => key === name)?.[1];
}

export function setSessionCookie(reply: FastifyReply, sessionId: string): void {
  reply.header(
    "Set-Cookie",
    [
      `${sessionCookieName}=${sessionId}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Max-Age=28800"
    ].join("; ")
  );
}

export function clearSessionCookie(reply: FastifyReply): void {
  reply.header(
    "Set-Cookie",
    [
      `${sessionCookieName}=`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Max-Age=0"
    ].join("; ")
  );
}

