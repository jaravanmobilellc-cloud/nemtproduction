import { defineMiddleware } from "astro/middleware";
import { jwtVerify } from "jose";
import { env } from 'cloudflare:workers';

const protectedPaths = ['/dashboard'];

export const onRequest = defineMiddleware(async (context, next) => {
    const cookies = context.request.headers.get('cookie') || '';
    const tokenCookie = cookies.split('; ').find((row) => row.startsWith('session_token='));
    const token = tokenCookie ? tokenCookie.split('=')[1] : null;

    if (!token) {
        context.locals.userId = null;
        if (protectedPaths.some((path) => context.url.pathname.startsWith(path))) {
            return context.redirect('/login');
        }
        return next();
    }

    try {
        const secret = new TextEncoder().encode(env.JWT_SECRET as string);
        const { payload } = await jwtVerify(token, secret);
        context.locals.userId = payload.userId as string;
    } catch {
        context.locals.userId = null;
        if (protectedPaths.some((path) => context.url.pathname.startsWith(path))) {
            return context.redirect('/login');
        }
    }

    return next();
});