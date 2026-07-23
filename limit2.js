'use strict';

/**
 * Demo — PROTECTED auth surfaces (rate-limit on every route).
 * After a repository code scan, these should NOT appear as rate_limit_missing.
 */

const express = require('express');
const rateLimit = require('express-rate-limit');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
});

// login / auth
router.post('/secure/login', loginLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/signin', loginLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/sign-in', loginLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/authenticate', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/authentication', authLimiter, (req, res) => res.sendStatus(401));

// password
router.post('/secure/change-password', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/update-password', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/passwd', authLimiter, (req, res) => res.sendStatus(401));

// forgot / reset / recovery (card)
router.post('/secure/forgot-password', authLimiter, (req, res) => res.json({ ok: true }));
router.post('/secure/reset-password', authLimiter, (req, res) => res.json({ ok: true }));
router.post('/secure/password-reset', authLimiter, (req, res) => res.json({ ok: true }));
router.post('/secure/recovery', authLimiter, (req, res) => res.json({ ok: true }));
router.post('/secure/account-recover', authLimiter, (req, res) => res.json({ ok: true }));

// PIN / unlock
router.post('/secure/pin', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/pin-recovery', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/unlock', authLimiter, (req, res) => res.sendStatus(401));

// MFA / OTP / 2FA
router.post('/secure/otp', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/mfa', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/2fa', authLimiter, (req, res) => res.sendStatus(401));
router.post('/secure/verify-otp', authLimiter, (req, res) => res.sendStatus(401));

module.exports = router;
