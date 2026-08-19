# `@complicatedauth/server`

Secret-holding BFF companion for `@complicatedauth/browser`. It maps browser-safe opaque tokens to ComplicatedAuth login/session references and proxies the stable `/auth` protocol.

```ts
import {createClient} from "redis";
import {RedisReferenceStore} from "@complicatedauth/server";

const redis = createClient({url: process.env.REDIS_URL});
await redis.connect();

const auth = new ComplicatedAuthServer({
  backendUrl: process.env.COMPLICATEDAUTH_URL!,
  projectUid: process.env.COMPLICATEDAUTH_PROJECT_UID!,
  apiKey: process.env.COMPLICATEDAUTH_API_KEY!,
  store: new RedisReferenceStore({client: redis}),
});

export const GET = (request: Request) => auth.handle(request);
export const POST = (request: Request) => auth.handle(request);
export const DELETE = (request: Request) => auth.handle(request);
```

`RedisReferenceStore` stores only server-side login and session references, uses Redis expiry for their authoritative TTL, and can be shared across application instances. The application owns the Redis connection lifecycle. `MemoryReferenceStore` remains intended only for development and tests because browser tokens are bearer credentials.
