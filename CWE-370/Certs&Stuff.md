0. What is a Certificate?

A certificate is a digital ID card - "This entity is who they claim to be, and a trusted authority vouches for it."

    CA (Certificate Authority): The trusted authority that issues certificates - think of it as the government that prints passports. It signs each certificate cryptographically, so anyone can verify the signature without calling the CA directly.

    Certificate: The passport itself. It contains the holder's identity, a public key, an expiry date, and the CA's signature. Presenting a valid, signed certificate to a server is how a client proves who they are.

    PKI (Public Key Infrastructure): The overall system - CAs, certificates, revocation lists - that makes this chain of trust work. 

Important: A certificate can be declared invalid before it expires. That's revocation.

---

1. The "Source of Truth" vs. The "Snapshot"

Think of the session as a photocopy of someone's ID taken at the front door. Security checks the original at entry and makes a copy. If that ID gets cancelled an hour later - reported stolen, or the person is fired - the photocopy at the door still looks fine. Nobody updated it.

    CRL (Certificate Revocation List): The live "blacklist" maintained by the CA. It lists certificates that have been declared void before their expiry - compromised keys, terminated employees, detected misuse. In the demo, revocation_list is this list.

    Session State: The photocopy. When Alice logs in, the app records: "Alice was valid at this moment." CWE-370 happens because the app keeps trusting the photocopy instead of checking the original.

---

2. Why Sessions Exist (and Why They Create the Trap)

HTTP is stateless - every request arrives with no memory of the last one. To recognise Alice on her second request, the server issues a Session Token (a random string stored in a cookie) and ties it to her identity in a server-side dictionary.

This is fine. The trap is a false assumption that follows from it:

    Authentication (who you are) is not the same as Authorisation (are you still allowed to be here?).

Developers often treat an active session as proof of both. It is only proof of the first. The session says "Alice logged in successfully." It says nothing about whether Alice's certificate is still valid right now. That requires going back to the source of truth - the CRL - on every request.

---

3. Propagation Delay

This is the "danger zone" between Step 3 and Step 4.

    Definition: The time it takes for a security change to actually take effect across all parts of a system.

    Think of a scenario where a bank flags a stolen card at 9am. But the ATM at the airport is running an offline copy of the block list from 6 hours ago. The card still works at that ATM. The revocation happened - it just hasn't propagated there yet.

---

4. The Real-World Fix: Middleware

"Do I have to paste that CRL check into every single route?"

No that's why we use Middleware.

    Middleware: A layer of code that intercepts every incoming request before it reaches any route handler. It runs first, always.

    The pattern: In production, you wouldn't write the revocation check inside /safe/dashboard. You'd write it once in middleware, so every protected route gets it automatically. If the cert is revoked, the middleware rejects the request before the route logic even runs.

---

5. OCSP vs. CRL

CRL and OSCP Improvements

    CRL (The List): The CA publishes a file listing all revoked certificate IDs. Servers download it and search it. For a large CA, this file can be megabytes in size and is only republished every few hours - meaning a certificate revoked at 9am might still appear valid in a cached CRL until the next issuance cycle.

    OCSP (Online Certificate Status Protocol): Instead of maintaining a local copy of the list, the server sends a real-time query to the CA: "Is certificate X valid right now?" The CA responds immediately. More accurate, but adds a network round-trip on every check.

    OCSP Stapling: A performance optimisation. Rather than the client querying the CA directly, the server fetches a time-stamped signed response from the CA ("this cert was valid as of 10:03am") and attaches it to the TLS handshake. The client gets freshness proof without making a separate request.

---

Summary

    "The vulnerability isn't that we didn't check the certificate - it's that we trusted a past result in a present context. We treated security as an event (at login) rather than a continuous state."