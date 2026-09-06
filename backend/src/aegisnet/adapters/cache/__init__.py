"""Redis access: the client, the fixed-window rate limiter and the access-token denylist.

Nothing here caches a response; the brief cache is content-addressed inside the Perplexity
client, which is where the key that identifies an answer is computed."""
