# Attack Surface

## Priority View
- High-risk entry points: 6
- Public exposure candidates (static inference): 270
- Internal exposure candidates (static inference): 0
- Routes with unknown exposure: 0
- Routes with likely data access: 0
- Routes with outbound trust boundaries: 0

## Highest-Risk Entry Points
- POST /file-upload (server.ts) -> upload; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- POST /profile/image/file (server.ts) -> upload; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- GET /rest/admin/application-configuration (server.ts) -> admin; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- GET /rest/admin/application-version (server.ts) -> admin; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- GET /rest/user/authentication-details (server.ts) -> auth; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- POST /rest/user/login (server.ts) -> auth; evidence: static_observed; auth enforcement: unknown; no auth signals observed

## Auth And Privileged Routes
- [HIGH] GET /rest/admin/application-configuration (server.ts) -> admin, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [HIGH] GET /rest/admin/application-version (server.ts) -> admin, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [HIGH] GET /rest/user/authentication-details (server.ts) -> auth, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [HIGH] POST /rest/user/login (server.ts) -> auth, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [MEDIUM] GET /https:/www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token= (frontend/src/app/Services/user.service.ts) -> auth, public; evidence: static_observed; auth enforcement: unknown; auth signals: oauth

## Public Application Routes
- [HIGH] POST /file-upload (server.ts) -> upload, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [HIGH] POST /profile/image/file (server.ts) -> upload, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET / (routes/dataErasure.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] POST / (routes/dataErasure.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] OPTIONS /* (server.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; auth signals: auth_middleware
- [LOW] GET /api/Addresss (server.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /api/Addresss (data/static/codefixes/changeProductChallenge_1.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /api/Addresss (data/static/codefixes/changeProductChallenge_2.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /api/Addresss (data/static/codefixes/changeProductChallenge_3_correct.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /api/Addresss (data/static/codefixes/changeProductChallenge_4.ts) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed

## Operational, Internal, And Unknown-Exposure Routes
- [LOW] GET /metrics (server.ts) -> health, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /metrics (data/static/codefixes/exposedMetricsChallenge_1.ts) -> health, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /metrics (data/static/codefixes/exposedMetricsChallenge_2.ts) -> health, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed
- [LOW] GET /metrics (data/static/codefixes/exposedMetricsChallenge_3_correct.ts) -> health, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed

## External Dependencies
- Repository context; route ownership is not established by these signals.
- /api/Challenges/
- /rest/admin/application-configuration
- http://192.168.99.100:3000
- http://192.168.99.100:4200
- http://bit.ly/2YIjdt7
- http://futurama.wikia.com/wiki/Suicide_booth
- http://gitter.im/bkimminich/juice-shop
- http://htmledit.squarefree.com
- http://penguin.termina.linux.test:3000
- http://penguin.termina.linux.test:4200
- http://rickandmorty.wikia.com/wiki/Snuffles
- http://www.alte-postleitzahlen.de/uetersen
- http://www.olea.com.ro/
- http://www.userlogos.org/files/logos/inductiveload/Google%20Code.png
- https://2019.open-security-summit.org/img/blocks/ticket.png
- https://20thanniversary.owasp.org/
- https://20thanniversary.owasp.org/\
- https://7minsec.com/favicon.ico
- https://7ms.us/7ms-294-gdpr-me-asap/
- https://7ms.us/slack
- https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm
- https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm\
- https://blog.mozilla.org/press/
- https://bodgeit.herokuapp.com/search.jsp?q=Whatsit+taste+like
- https://bsky.app/profile/defcon.bsky.social

## Secrets And Auth Hints
- Secret-related env usage: LLM_API_KEY (data/static/codefixes/chatbotGreedyInjectionChallenge_1.ts)
- Secret-related env usage: LLM_API_KEY (data/static/codefixes/chatbotGreedyInjectionChallenge_2_correct.ts)
- Secret-related env usage: LLM_API_KEY (data/static/codefixes/chatbotGreedyInjectionChallenge_3.ts)
- Secret-related env usage: LLM_API_KEY (data/static/codefixes/chatbotGreedyInjectionChallenge_4.ts)
- Secret-related env usage: eyJh… (frontend/src/app/app.guard.spec.ts)
- Secret-related env usage: 0x36… (frontend/src/app/faucet/faucet.component.ts)
- Secret-related env usage: eyJh… (frontend/src/app/last-login-ip/last-login-ip.component.spec.ts)
- Secret-related env usage: eyJh… (frontend/src/app/last-login-ip/last-login-ip.component.spec.ts)
- Secret-related env usage: IamU… (frontend/src/app/login/login.component.ts)
- Secret-related env usage: 1AbK… (frontend/src/app/payment/payment.component.spec.ts)
- Secret-related env usage: Xr55… (frontend/src/app/payment/payment.component.spec.ts)
- Secret-related env usage: 1AbK… (frontend/src/app/payment/payment.component.ts)
- Secret-related env usage: Xr55… (frontend/src/app/payment/payment.component.ts)
- Secret-related env usage: -----BEGIN RSA PRIVATE KEY----- (lib/insecurity.ts)
- Secret-related env usage: CTF_KEY (lib/utils.ts)
- Secret-related env usage: CTF_KEY (lib/utils.ts)
- Secret-related env usage: LLM_API_KEY (routes/chat.ts)
- Secret-related env usage: ALCHEMY_API_KEY (routes/nftMint.ts)
- Secret-related env usage: ALCHEMY_API_KEY (routes/web3Wallet.ts)
- Secret-related env usage: ALCHEMY_API_KEY (test/api/nftMint.test.ts)
- Secret-related env usage: ALCHEMY_API_KEY (test/api/nftMint.test.ts)
- Secret-related env usage: ALCHEMY_API_KEY (test/api/nftMint.test.ts)
- Secret-related env usage: ALCHEMY_API_KEY (test/api/nftMint.test.ts)
- Secret-related env usage: eyJh… (test/api/user.test.ts)
- Secret-related env usage: ALCHEMY_API_KEY (test/api/web3Wallet.test.ts)
- Auth-related keywords observed: api_key, apikey, auth_middleware, bearer_token, dockerfile_no_user_directive, gha_no_top_level_permissions, jwt, oauth, shell_sudo_used
