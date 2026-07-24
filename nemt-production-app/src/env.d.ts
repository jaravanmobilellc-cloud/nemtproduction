declare namespace App {
    interface Locals {
        userId: string | null;
    }
    interface Runtime {
        env: {
            DB: D1Database;
            JWT_SECRET: string;
        };
    }
}