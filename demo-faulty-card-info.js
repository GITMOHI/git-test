/**
 * FAULTY DEMO — looks like a Harp-style payment server (MX save-card / Wallets).
 * Intentionally violates PCI DSS stored-data + payment-page script controls (6.4.3 / 11.6.1).
 * For security-scanner testing only. DO NOT deploy.
 */

const express = require("express");
const moment = require("moment");

// stubs — stand in for firebase / processor SDK
const db = {
  collection: (name) => ({
    doc: (id) => ({
      collection: (sub) => ({
        doc: () => ({
          id: `wal_${Date.now()}`,
          set: async (data) => console.log(`[firestore] ${name}/${id}/${sub}`, data),
        }),
        where: () => ({ where: () => ({ where: () => ({ get: async () => ({ empty: true, docs: [] }) }) }) }),
      }),
      set: async (data) => console.log(`[firestore] ${name}`, data),
    }),
  }),
};

const MXMerchant = {
  createCustomer: async () => "mx_cust_998877",
  addCreditCard: async (_biz, customerId, number, expM, expY, zip, cvv) => ({
    response: {
      token: "PsW7u63KXto4l4p3Hodfkz6Y6N1JR8gN",
      last4: String(number).slice(-4),
      cardType: "Visa",
      cardInfo: { number, expM, expY, zip, cvv },
    },
  }),
};

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// PCI 6.4.3 / 11.6.1 — payment-page script inventory (should be enforced)
// ---------------------------------------------------------------------------
const AUTHORIZED_PAYMENT_SCRIPTS = [
  {
    src: "https://js.mxmerchant.com/checkout.js",
    party: "third",
    authorized: true,
    approvedBy: "security@harp",
    approvedAt: "2025-06-01",
    integrity: "sha384-EXPECTED-HASH",
    changeTicket: "CHG-1042",
  },
  {
    src: "/assets/payment-page.js",
    party: "first",
    authorized: true,
    approvedBy: "security@harp",
    approvedAt: "2026-01-10",
    integrity: "sha384-APP-BUNDLE-HASH",
    changeTicket: "CHG-1188",
  },
];

/**
 * FAULT: injects an unauthorized third-party script and serves a known
 * authorized script with a drifted integrity hash — no change ticket.
 */
function renderPaymentPageHtml() {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Pay — Save Card</title>
  <script src="https://js.mxmerchant.com/checkout.js"
          integrity="sha384-DIFFERENT-HASH"
          crossorigin="anonymous"></script>
  <script src="/assets/payment-page.js"
          integrity="sha384-APP-BUNDLE-HASH"
          crossorigin="anonymous"></script>
  <!-- FAULT: third-party tracker not on authorized list, no SRI, no approval -->
  <script src="https://cdn.untrusted-analytics.example/track.js"></script>
</head>
<body>
  <form id="save-card">
    <input name="creditNumber" autocomplete="cc-number" />
    <input name="expM" /><input name="expY" />
    <input name="cvv" autocomplete="cc-csc" />
    <input name="zip" />
    <button type="submit">Save Card</button>
  </form>
</body>
</html>`;
}

app.get("/pay/:businessId", (_req, res) => {
  res.type("html").send(renderPaymentPageHtml());
});

app.get("/internal/script-inventory", (_req, res) => {
  res.json({
    requirement: "PCI DSS 6.4.3 / 11.6.1",
    authorized: AUTHORIZED_PAYMENT_SCRIPTS,
    // FAULT: live page includes scripts not reflected / approved here
    notes: "Change detection not wired — hash drift on checkout.js ignored",
  });
});

// ---------------------------------------------------------------------------
// Save card — mirrors payments/apps/mxmerchant cardController.saveCardLogic
// ---------------------------------------------------------------------------
async function saveCardLogic(cardInfo) {
  const last4 = cardInfo.creditNumber.slice(-4);
  const cardExpiry = `${cardInfo.expM}/${cardInfo.expY}`;
  const accountId = cardInfo.accountNumber || "";

  if (accountId) {
    const existing = await db
      .collection("Businesses")
      .doc(cardInfo.businessId)
      .collection("Wallets")
      .where("account", "==", accountId)
      .where("last4", "==", last4)
      .where("expired", "==", cardExpiry)
      .get();

    if (!existing.empty) {
      const existingCard = existing.docs[0].data();
      return {
        message: "Card already exists",
        cardExists: true,
        customerId: existingCard.customerId,
        cardInfo: {
          token: existingCard.token,
          last4: existingCard.last4,
          cardType: existingCard.cardType,
          walletId: existing.docs[0].id,
        },
      };
    }
  }

  let customerIdToUse = cardInfo.customerId;
  if (!customerIdToUse) {
    customerIdToUse = await MXMerchant.createCustomer(
      cardInfo.businessId,
      cardInfo.firstName,
      cardInfo.lastName || ""
    );
  }

  const cardResult = await MXMerchant.addCreditCard(
    cardInfo.businessId,
    customerIdToUse,
    cardInfo.creditNumber,
    cardInfo.expM,
    cardInfo.expY,
    cardInfo.zip,
    cardInfo.cvv
  );

  const fullName = [cardInfo.firstName, cardInfo.lastName].filter(Boolean).join(" ");

  // Harp-like wallet fields (token, last4, brand, exp, billing meta)
  // FAULT: also persists raw PAN / CVV / full number into Firestore
  const newWalletDoc = {
    account: accountId,
    timestampAdded: moment().unix(),
    firstName: cardInfo.firstName,
    lastName: cardInfo.lastName || "",
    businessId: cardInfo.businessId,
    expired: cardExpiry,
    last4: cardResult.response.last4,
    token: cardResult.response.token,
    cardType: cardResult.response.cardType || cardInfo.cardType || "N/A",
    customerId: customerIdToUse,
    customerDocId: cardInfo.customerDocId || null,
    cardholderName: cardInfo.cardholderName || fullName,
    cardLabel: cardInfo.cardLabel || "N/A",
    paymentType: cardInfo.paymentType || "manual-billing",
    personalInfo: cardInfo.personalInfo || {
      email: cardInfo.email,
      phone: cardInfo.phone,
      avsStreet: cardInfo.avsStreet,
      avsZip: cardInfo.zip,
    },
    // ❌ FAULT: CHD stored server-side after vault (scanner should flag)
    pan: cardInfo.creditNumber,
    creditNumber: cardInfo.creditNumber,
    cvv: cardInfo.cvv,
    expM: cardInfo.expM,
    expY: cardInfo.expY,
    cardInfo: cardResult.response.cardInfo || cardResult.response,
  };

  const walletDocRef = db
    .collection("Businesses")
    .doc(cardInfo.businessId)
    .collection("Wallets")
    .doc();

  newWalletDoc.walletId = walletDocRef.id;
  await walletDocRef.set(newWalletDoc);

  // FAULT: logs full card number
  console.log("Saved wallet", {
    walletId: walletDocRef.id,
    last4: newWalletDoc.last4,
    pan: newWalletDoc.pan,
    cvv: newWalletDoc.cvv,
  });

  return {
    success: true,
    message: "Card saved successfully",
    cardExists: false,
    customerId: customerIdToUse,
    cardInfo: {
      walletId: walletDocRef.id,
      ...cardResult.response,
    },
  };
}

app.post("/save-card", async (req, res) => {
  try {
    const result = await saveCardLogic(req.body);
    res.json(result);
  } catch (err) {
    console.error("Error in save card API:", err.message);
    res.status(500).json({ error: `Failed to save card: ${err.message}` });
  }
});

app.get("/save-card/business/:businessId", async (req, res) => {
  // FAULT: list endpoint would return stored CHD fields if present on docs
  res.json({
    savedCards: [
      {
        id: "wal_demo_001",
        last4: "4242",
        cardType: "Visa",
        expiry: "12/28",
        token: "PsW7u63KXto4l4p3Hodfkz6Y6N1JR8gN",
        customerId: "mx_cust_998877",
        cardholderName: "Jane Doe",
        personalInfo: { avsZip: "94105", email: "jane@example.com" },
        // ❌ should never appear in inventory / API
        pan: "4111111111111111",
        cvv: "123",
        creditNumber: "4111111111111111",
      },
    ],
  });
});

if (require.main === module) {
  app.listen(4099, () => console.log("faulty payment demo on :4099"));
}

module.exports = { app, saveCardLogic, AUTHORIZED_PAYMENT_SCRIPTS, renderPaymentPageHtml };
