# Roadmap
- [x] Homepage: 3 steps, public vs private, 3 cards, pricing, FAQ
- [x] /about rewritten as sovereign identity platform (4 languages)
- [x] Dev guides: blind-hash-matching, graduated-consent, email-sync-webhooks
- [x] Consumer pages: connected-apps, no-account-lists
- [x] Console: team write access to apps (app code)
- [x] Database rule db/0211_oauth_client_team_write.sql applied
- [x] Account & Security: email change chooser with per-app selection and per-app results
- [x] Scope identity:handle_reservation (id_token, userinfo, refresh; rate limited, integrity checked)
- [x] Remove leftover linked_accounts texts and non-existent handle webhook from console, guides and AI prompts
- [ ] Keys: WALLET_ID_SECRET, CARD_LIVENESS_SECRET, Google Wallet issuer (needs owner)
- [ ] Signed-in browser test of console at 390/810/1280 (needs a ROUT test account)
- [ ] FR/DE versions of the new developer guides

## Wallet / ROUT card (Nov 11)
- [ ] Wallet page: ROUT card QR not visible
- [ ] "Add to Google Wallet" on ROUT card adds the profile card instead of the ROUT card (Sovereign Key with rotating QR)
- [ ] ROUT card design in Google Wallet
- [ ] Command Center ROUT card widget: more useful
- [ ] Claiming a ROUT card requires active 2FA
- [ ] Viewing private card details requires fresh verification each time (passkey, SMS, recovery code, password)
- [ ] Card rotation on desktop broken; no "move your phone" hint on desktop
- [ ] Remove "Save to contacts" from cards
- [ ] Homepage "One identity, three levels": 2 profile cards linking to profile hubs + 1 private functional card (NFC)
- [ ] ROUT card: block, freeze, replace with high security
- [ ] Uploaded directives (PQC, Merchant demo, Zero-seed wallet, PASS summary): not requested yet; Zero-seed conflicts with rotating QR in Google Wallet
