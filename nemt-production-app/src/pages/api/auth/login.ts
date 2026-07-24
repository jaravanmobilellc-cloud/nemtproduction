import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { SignJWT } from 'jose';
import { buildCsrfCookie, buildSessionCookie, generateCsrfToken, hashPassword, jsonResponse, verifyPassword } from '../../../lib/auth';

const loginAttempts = new Map<string, { count: number; expiresAt: number }>();

function getClientIp(request: Request) {
    return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
}

function isRateLimited(request: Request) {
    const ip = getClientIp(request);
    const now = Date.now();
    const attempt = loginAttempts.get(ip);

    if (!attempt) {
        loginAttempts.set(ip, { count: 1, expiresAt: now + 60_000 });
        return false;
    }

    if (now > attempt.expiresAt) {
        loginAttempts.set(ip, { count: 1, expiresAt: now + 60_000 });
        return false;
    }

    if (attempt.count >= 5) {
        return true;
    }

    loginAttempts.set(ip, { count: attempt.count + 1, expiresAt: attempt.expiresAt });
    return false;
}

type UserRecord = {
    id: string | number;
    username?: string;
    password_hash?: string;
    password?: string;
};

type LoginBody = {
    username?: string;
    password?: string;
};

export const POST: APIRoute = async (context) => {
    const { request } = context;

    try {
        const requestCsrfToken = request.headers.get('x-csrf-token');
        const expectedToken = context.cookies.get('csrf_token');

        if (!expectedToken || requestCsrfToken !== expectedToken) {
            return jsonResponse({ error: 'Invalid CSRF token.' }, 403);
        }

        const body = (await request.json().catch(() => ({}))) as LoginBody;
        const username = body.username?.trim();
        const password = body.password?.trim();

        if (!username || !password) {
            return jsonResponse({ error: 'Username and password are required.' }, 400);
        }

        if (isRateLimited(request)) {
            return jsonResponse({ error: 'Too many login attempts. Please try again later.' }, 429);
        }

        const db = env.DB as { prepare: (query: string) => { bind: (...args: unknown[]) => { first: () => Promise<UserRecord | null>; all: () => Promise<{ results: UserRecord[] }> }; } };
        const jwtSecret = env.JWT_SECRET as string;

        if (!db || !jwtSecret) {
            return jsonResponse({ error: 'Authentication environment is unavailable.' }, 500);
        }

        const user = (await db
            .prepare('SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1')
            .bind(username)
            .first()) as UserRecord | null;

        const storedPassword = user?.password_hash ?? user?.password;
        const passwordValid = await verifyPassword(password, storedPassword);

        if (!user || !passwordValid) {
            return jsonResponse({ error: 'Invalid username or password.' }, 401);
        }

        if (!user.password_hash && storedPassword) {
            const hashedPassword = await hashPassword(password);
            await db
                .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                .bind(hashedPassword, user.id)
                .run();
        }

        const token = await new SignJWT({ userId: String(user.id) })
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setExpirationTime('7d')
            .sign(new TextEncoder().encode(jwtSecret));

        const csrfToken = generateCsrfToken();
        const headers = new Headers();
        headers.append('Set-Cookie', buildSessionCookie(token, request.url));
        headers.append('Set-Cookie', buildCsrfCookie(csrfToken, request.url));
        return jsonResponse({ success: true, csrfToken }, 200, headers);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return jsonResponse({ error: 'Server error: ' + message }, 500);
    }
};