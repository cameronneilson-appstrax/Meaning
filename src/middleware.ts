import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

// Pages that require the user to be logged in
const PROTECTED_PAGES = ["/account", "/connect-analytics"];

export async function middleware(req: NextRequest) {
  // Redirect www to non-www so auth cookies and OAuth callbacks stay consistent
  if (req.nextUrl.hostname === "www.usemeaning.io") {
    const url = req.nextUrl.clone();
    url.host = "usemeaning.io";
    url.protocol = "https:";
    return NextResponse.redirect(url, 301);
  }

  const { pathname } = req.nextUrl;

  // Only gate page routes — API routes handle their own auth via `auth()`
  const needsAuth = PROTECTED_PAGES.some((p) => pathname.startsWith(p));
  if (!needsAuth) return NextResponse.next();

  console.log("AUTH_SECRET", process.env.AUTH_SECRET);
  console.log(req);
  const nextAuthUrl = process.env.NEXTAUTH_URL ?? "";
  const isProductionUsemeaning =
    nextAuthUrl.startsWith("https://") && nextAuthUrl.includes("usemeaning.io");
  const token = await getToken({
    req,
    secret: process.env.AUTH_SECRET,
    secureCookie: isProductionUsemeaning,
  });

  console.log("token", token);
  if (!token) {
    const loginUrl = new URL("/login", req.url);
    if (pathname.startsWith("/connect-analytics")) {
      loginUrl.searchParams.set("callbackUrl", "/connect-analytics");
    }
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/account/:path*",
    "/connect-analytics/:path*",
    "/((?!_next/static|_next/image|favicon.ico|api/).*)",
  ],
};
