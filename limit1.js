'use strict';

/**
 * Demo — UNPROTECTED auth surfaces (no rate-limit / lockout).
 * After a repository code scan, every route below should appear as rate_limit_missing.
 */

const express = require('express');
const router = express.Router();

// login / auth
router.post('/api/login', (req, res) => res.sendStatus(401));
router.post('/api/signin', (req, res) => res.sendStatus(401));
router.post('/api/sign-in', (req, res) => res.sendStatus(401));
router.post('/api/authenticate', (req, res) => res.sendStatus(401));
router.post('/api/authentication', (req, res) => res.sendStatus(401));

// password
router.post('/api/change-password', (req, res) => res.sendStatus(401));
router.post('/api/update-password', (req, res) => res.sendStatus(401));
router.post('/api/passwd', (req, res) => res.sendStatus(401));

// forgot / reset / recovery (card)
router.post('/api/forgot-password', (req, res) => res.json({ ok: true }));
router.post('/api/reset-password', (req, res) => res.json({ ok: true }));
router.post('/api/password-reset', (req, res) => res.json({ ok: true }));
router.post('/api/recovery', (req, res) => res.json({ ok: true }));
router.post('/api/account-recover', (req, res) => res.json({ ok: true }));

// PIN / unlock
router.post('/api/pin', (req, res) => res.sendStatus(401));
router.post('/api/pin-recovery', (req, res) => res.sendStatus(401));
router.post('/api/unlock', (req, res) => res.sendStatus(401));

// MFA / OTP / 2FA
router.post('/api/otp', (req, res) => res.sendStatus(401));
router.post('/api/mfa', (req, res) => res.sendStatus(401));
router.post('/api/2fa', (req, res) => res.sendStatus(401));
router.post('/api/verify-otp', (req, res) => res.sendStatus(401));

module.exports = router;
