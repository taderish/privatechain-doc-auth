# PrivateChain Document Authentication Library

A decentralized, privacy-first system for managing, storing, and securely sharing authenticated documents on-chain using Clarity smart contracts. Designed with robust permissioning, verifiability, and classification logic.

---

## 🚀 Features

- Register and store document metadata securely on-chain
- Assign view/edit/full access to authorized users with expiration support
- Strong format validation and classification checks
- Audit-friendly document modification with security layers
- Optimized storage and alternative registration flows
- Strict error handling using predefined error codes

---

## 🧱 Smart Contract Architecture

This Clarity-based system includes the following components:

- **Document Repository:** Main storage structure for document records
- **Access Control Map:** Permission registry for authorized users
- **Validation Utilities:** Tag, digest, descriptor, and classification format verifiers
- **Access Types:** `view`, `edit`, and `full` permissions
- **Error Handling:** Centralized constant-based error system for clarity

---

## 🛠️ Public Functions

- `register-document`: Add new documents to the system
- `modify-document`: Update a document you own
- `authorize-access`: Grant permission to others
- `enhanced-document-modification`: Cleaner version of modify
- `secure-document-update`: Security-enhanced document edit
- `advanced-document-registration`: Optimized registration with alternative map

---

## 📑 Error Codes

| Code | Description                    |
|------|--------------------------------|
| 200  | Not authorized                 |
| 201  | Document already exists        |
| 202  | Document not found             |
| 203  | Invalid document data          |
| 204  | Invalid descriptor             |
| 205  | Invalid access type            |
| 206  | Invalid timestamp              |
| 207  | Access denied                  |
| 208  | Invalid classification         |

---

## 🔐 Access Types

- `view`: Read-only access
- `edit`: Can modify content if allowed
- `full`: Full control over document and permissions

---

## ⏳ Time Units

All durations are expressed in block height units (approx. 10-minute intervals).
- `u52560` = ~1 year of blocks

---

## 📦 Storage Maps

- `document-repository`
- `document-access-permissions`
- `optimized-document-storage`

---

