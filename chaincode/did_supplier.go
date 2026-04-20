// Package main implements the DID-based Supplier Identity Chaincode for
// Hyperledger Fabric v2.5. It provides:
//   - Supplier DID registration anchored to MSP identity
//   - Real-time credential verification (VerifySupplier)
//   - Certificate Revocation List (CRL) checking
//   - Zero-Trust audit logging
//   - Purchase Order gating — only verified suppliers may submit POs
//
// Course: CIS6372 Information Assurance
// Author: Dan ZHANG

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ─── Data Models ─────────────────────────────────────────────────────────────

// SupplierDID represents a W3C-compliant Decentralized Identifier record
// anchored on the permissioned blockchain.
type SupplierDID struct {
	DID            string    `json:"did"`             // e.g. "did:fabric:supplier:ABC-001"
	MSPID          string    `json:"mspId"`           // Fabric MSP identifier
	LegalName      string    `json:"legalName"`
	CertThumbprint string    `json:"certThumbprint"`  // SHA-256 of X.509 cert
	Status         string    `json:"status"`          // "ACTIVE" | "REVOKED" | "SUSPENDED"
	RegisteredAt   time.Time `json:"registeredAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Credentials    []VC      `json:"verifiableCredentials"`
}

// VC is a simplified Verifiable Credential attached to a supplier DID.
type VC struct {
	Type      string    `json:"type"`       // e.g. "BusinessLicense", "ISO9001"
	Issuer    string    `json:"issuer"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
}

// PurchaseOrder is gated behind VerifySupplier — only authenticated
// suppliers can create a PO on the ledger.
type PurchaseOrder struct {
	POID        string    `json:"poId"`
	SupplierDID string    `json:"supplierDid"`
	Items       []POItem  `json:"items"`
	TotalValue  float64   `json:"totalValue"`
	Status      string    `json:"status"`   // "PENDING" | "APPROVED" | "REJECTED"
	CreatedAt   time.Time `json:"createdAt"`
}

// POItem is a line item within a purchase order.
type POItem struct {
	SKU      string  `json:"sku"`
	Quantity int     `json:"quantity"`
	UnitPrice float64 `json:"unitPrice"`
}

// AuditLog records every access attempt for NIST RMF "Monitor" phase compliance.
type AuditLog struct {
	EventID     string    `json:"eventId"`
	SupplierDID string    `json:"supplierDid"`
	Action      string    `json:"action"`
	Outcome     string    `json:"outcome"`   // "ALLOWED" | "BLOCKED"
	Reason      string    `json:"reason"`
	CallerMSP   string    `json:"callerMsp"`
	Timestamp   time.Time `json:"timestamp"`
}

// ─── Contract ────────────────────────────────────────────────────────────────

// SmartContract implements the chaincode interface.
type SmartContract struct {
	contractapi.Contract
}

// ─── Supplier Registration ────────────────────────────────────────────────────

// RegisterSupplier anchors a new DID to the blockchain ledger.
// Only the ProcurementMSP admin may call this function.
func (s *SmartContract) RegisterSupplier(
	ctx contractapi.TransactionContextInterface,
	did string,
	legalName string,
	certThumbprint string,
	validityDays int,
) error {
	// Enforce caller is from ProcurementMSP
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get caller MSP: %w", err)
	}
	if mspID != "ProcurementMSP" {
		_ = s.writeAuditLog(ctx, did, "REGISTER", "BLOCKED", "Caller is not ProcurementMSP")
		return fmt.Errorf("ACCESS DENIED: only ProcurementMSP can register suppliers")
	}

	// Check for duplicate DID
	existing, err := ctx.GetStub().GetState(did)
	if err != nil {
		return fmt.Errorf("ledger read error: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("DID already registered: %s", did)
	}

	now := time.Now().UTC()
	supplier := SupplierDID{
		DID:            did,
		MSPID:          "SupplierMSP",
		LegalName:      legalName,
		CertThumbprint: certThumbprint,
		Status:         "ACTIVE",
		RegisteredAt:   now,
		ExpiresAt:      now.Add(time.Duration(validityDays) * 24 * time.Hour),
		Credentials:    []VC{},
	}

	data, err := json.Marshal(supplier)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	if err := ctx.GetStub().PutState(did, data); err != nil {
		return fmt.Errorf("ledger write error: %w", err)
	}

	_ = s.writeAuditLog(ctx, did, "REGISTER", "ALLOWED", "Supplier registered successfully")
	return nil
}

// ─── Core Identity Verification ───────────────────────────────────────────────

// VerifySupplier is the Zero-Trust gate called before any transaction execution.
// It checks: DID exists → status ACTIVE → certificate not expired → VCs valid.
// Returns an error (and writes an audit log) on any failure.
func (s *SmartContract) VerifySupplier(
	ctx contractapi.TransactionContextInterface,
	did string,
	certThumbprint string,
) (bool, error) {
	supplier, err := s.getSupplier(ctx, did)
	if err != nil {
		_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", "DID not found on ledger")
		return false, fmt.Errorf("ghost vendor attempt — DID not registered: %s", did)
	}

	// 1. Status check
	if supplier.Status != "ACTIVE" {
		reason := fmt.Sprintf("Supplier status is %s", supplier.Status)
		_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", reason)
		return false, fmt.Errorf("ACCESS DENIED: %s", reason)
	}

	// 2. Certificate thumbprint check (prevents cert swapping attacks)
	if supplier.CertThumbprint != certThumbprint {
		_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", "Certificate thumbprint mismatch")
		return false, fmt.Errorf("ACCESS DENIED: certificate thumbprint mismatch — possible identity spoofing")
	}

	// 3. Expiration check (acts as inline CRL)
	if time.Now().UTC().After(supplier.ExpiresAt) {
		_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", "DID credential expired")
		return false, fmt.Errorf("ACCESS DENIED: supplier identity has expired")
	}

	// 4. Verifiable Credential validity sweep
	for _, vc := range supplier.Credentials {
		if vc.Revoked {
			reason := fmt.Sprintf("Verifiable Credential of type '%s' is revoked", vc.Type)
			_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", reason)
			return false, fmt.Errorf("ACCESS DENIED: %s", reason)
		}
		if time.Now().UTC().After(vc.ExpiresAt) {
			reason := fmt.Sprintf("Verifiable Credential of type '%s' is expired", vc.Type)
			_ = s.writeAuditLog(ctx, did, "VERIFY", "BLOCKED", reason)
			return false, fmt.Errorf("ACCESS DENIED: %s", reason)
		}
	}

	_ = s.writeAuditLog(ctx, did, "VERIFY", "ALLOWED", "All checks passed")
	return true, nil
}

// ─── Purchase Order Submission ────────────────────────────────────────────────

// SubmitPurchaseOrder creates a PO on the ledger only after VerifySupplier passes.
// This is the core enforcement point: ghost vendors cannot create POs.
func (s *SmartContract) SubmitPurchaseOrder(
	ctx contractapi.TransactionContextInterface,
	poJSON string,
	certThumbprint string,
) error {
	var po PurchaseOrder
	if err := json.Unmarshal([]byte(poJSON), &po); err != nil {
		return fmt.Errorf("invalid PO JSON: %w", err)
	}

	// Zero-Trust gate — verify every time, regardless of history
	verified, err := s.VerifySupplier(ctx, po.SupplierDID, certThumbprint)
	if err != nil || !verified {
		return fmt.Errorf("PO rejected — supplier identity verification failed: %w", err)
	}

	po.Status = "PENDING"
	po.CreatedAt = time.Now().UTC()

	data, err := json.Marshal(po)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	key := "PO_" + po.POID
	return ctx.GetStub().PutState(key, data)
}

// ─── Credential Management ────────────────────────────────────────────────────

// AddVerifiableCredential attaches a VC (e.g. ISO 9001 cert) to a supplier DID.
func (s *SmartContract) AddVerifiableCredential(
	ctx contractapi.TransactionContextInterface,
	did, vcType, issuer string,
	validityDays int,
) error {
	supplier, err := s.getSupplier(ctx, did)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	vc := VC{
		Type:      vcType,
		Issuer:    issuer,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(validityDays) * 24 * time.Hour),
		Revoked:   false,
	}
	supplier.Credentials = append(supplier.Credentials, vc)

	data, _ := json.Marshal(supplier)
	return ctx.GetStub().PutState(did, data)
}

// RevokeSupplier changes DID status to REVOKED, instantly blocking all future access.
func (s *SmartContract) RevokeSupplier(
	ctx contractapi.TransactionContextInterface,
	did string,
) error {
	supplier, err := s.getSupplier(ctx, did)
	if err != nil {
		return err
	}
	supplier.Status = "REVOKED"
	data, _ := json.Marshal(supplier)
	_ = s.writeAuditLog(ctx, did, "REVOKE", "ALLOWED", "Supplier DID revoked by admin")
	return ctx.GetStub().PutState(did, data)
}

// QuerySupplier reads a supplier DID record (read-only).
func (s *SmartContract) QuerySupplier(
	ctx contractapi.TransactionContextInterface,
	did string,
) (*SupplierDID, error) {
	return s.getSupplier(ctx, did)
}

// QueryAuditLogs retrieves all audit log entries from the ledger.
func (s *SmartContract) QueryAuditLogs(
	ctx contractapi.TransactionContextInterface,
) ([]AuditLog, error) {
	iter, err := ctx.GetStub().GetStateByRange("AUDIT_", "AUDIT_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var logs []AuditLog
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			continue
		}
		var entry AuditLog
		if err := json.Unmarshal(kv.Value, &entry); err == nil {
			logs = append(logs, entry)
		}
	}
	return logs, nil
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

func (s *SmartContract) getSupplier(
	ctx contractapi.TransactionContextInterface,
	did string,
) (*SupplierDID, error) {
	data, err := ctx.GetStub().GetState(did)
	if err != nil {
		return nil, fmt.Errorf("ledger read error: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("DID not found: %s", did)
	}
	var supplier SupplierDID
	if err := json.Unmarshal(data, &supplier); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return &supplier, nil
}

func (s *SmartContract) writeAuditLog(
	ctx contractapi.TransactionContextInterface,
	did, action, outcome, reason string,
) error {
	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	txID := ctx.GetStub().GetTxID()

	entry := AuditLog{
		EventID:     "AUDIT_" + txID,
		SupplierDID: did,
		Action:      action,
		Outcome:     outcome,
		Reason:      reason,
		CallerMSP:   mspID,
		Timestamp:   time.Now().UTC(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState("AUDIT_"+txID, data)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating DID procurement chaincode: %s", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting chaincode: %s", err)
	}
}
