const HASH_PREFIX = 'pbkdf2_sha256';

function encodeBase64(bytes: Uint8Array): string {
    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return globalThis.btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
    const binary = globalThis.atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}

function createTimingSafeEqual(left: string, right: string): boolean {
    const leftBytes = new TextEncoder().encode(left);
    const rightBytes = new TextEncoder().encode(right);

    if (leftBytes.length !== rightBytes.length) {
        return false;
    }

    let result = 0;
    for (let index = 0; index < leftBytes.length; index += 1) {
        result |= leftBytes[index] ^ rightBytes[index];
    }

    return result === 0;
}

export async function hashPassword(password: string): Promise<string> {
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const iterations = 200_000;
    const passwordKey = await globalThis.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const derivedBits = await globalThis.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations,
        },
        passwordKey,
        256
    );

    return `${HASH_PREFIX}$${iterations}$${encodeBase64(salt)}$${encodeBase64(new Uint8Array(derivedBits))}`;
}

export async function verifyPassword(password: string, storedPassword: string | undefined): Promise<boolean> {
    if (!storedPassword) {
        return false;
    }

    if (!storedPassword.startsWith(`${HASH_PREFIX}$`)) {
        return createTimingSafeEqual(storedPassword, password);
    }

    const [, iterationsText, saltText, hashText] = storedPassword.split('$');
    const iterations = Number(iterationsText);
    const salt = decodeBase64(saltText);
    const expectedHash = hashText;

    const passwordKey = await globalThis.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const derivedBits = await globalThis.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations,
        },
        passwordKey,
        256
    );

    return createTimingSafeEqual(encodeBase64(new Uint8Array(derivedBits)), expectedHash);
}

export function buildSessionCookie(token: string, requestUrl: string): string {
    const isSecure = requestUrl.startsWith('https://');
    return `session_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${isSecure ? '; Secure' : ''}`;
}

export function buildCsrfCookie(token: string, requestUrl: string): string {
    const isSecure = requestUrl.startsWith('https://');
    return `csrf_token=${token}; Path=/; SameSite=Lax; Max-Age=604800${isSecure ? '; Secure' : ''}`;
}

export function generateCsrfToken(): string {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function getCsrfTokenFromCookie(cookieHeader: string | null): string | null {
    const cookies = cookieHeader?.split(';').map((cookie) => cookie.trim()) ?? [];
    const cookieValue = cookies.find((cookie) => cookie.startsWith('csrf_token='));
    return cookieValue ? decodeURIComponent(cookieValue.split('=')[1]) : null;
}

export function jsonResponse(body: unknown, status = 200, headers?: HeadersInit) {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            ...(headers instanceof Headers ? Object.fromEntries(headers.entries()) : headers),
        },
    });
}
