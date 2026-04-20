# DID-Based Supplier Identity Framework for Secure Procurement

CIS6372 Information Assurance — Final Project
Author: Dan ZHANG | Instructor: Iman Vakilinia

## Overview

This project implements a decentralized identity security framework to eliminate "ghost vendor" fraud in enterprise procurement systems. It integrates W3C Decentralized Identifiers (DIDs) anchored on Hyperledger Fabric v2.5, smart contract-based Zero-Trust verification, NIST RMF SP 800-37 continuous audit logging, and Verifiable Credentials (VCs) for supplier attribute certification.

## Repository Structure

- network/docker-compose.yml — Hyperledger Fabric 2-org network
- chaincode/did_supplier.go — Core smart contract (Go)
- simulation/simulate_evaluation.py — Python evaluation simulation

## Key Security Features

- Ghost vendor prevention: DID registry blocks unregistered entities at chaincode level
- Certificate pinning: SHA-256 thumbprint comparison prevents cert-swapping attacks
- Revocation: Instant status flip on ledger, no waiting for CRL distribution
- Zero-Trust: Every transaction re-verified regardless of prior auth history
- Audit trail: Immutable log entry written for every ALLOWED/BLOCKED event
- Performance: Credential caching reduces verification latency by 30%

## Evaluation Results

- Ghost-vendor interception rate: 100% (100/100 attacks blocked)
- Avg verification latency overhead: 25-40 ms per transaction
- System throughput at peak load: 342 TPS (Hyperledger Caliper)
- Latency at 350 TPS: 142 ms avg response time

## Running the Simulation

pip install cryptography tabulate matplotlib
python simulation/simulate_evaluation.py

## References

- Attaran, M. (2022). Blockchain Technology for Secure Supply Chain Management: A Comprehensive Review. IEEE Access. https://ieeexplore.ieee.org/document/9841565/
- Khan, S., & Naveed, M. (2025). Blockchain-Enabled Supply Chain Management: A Review of Security, Traceability, and Data Integrity. Applied Sciences, 15(9), 5168. https://www.mdpi.com/2076-3417/15/9/5168
- Wang, G. J., & Lee, H. L. (2025). Unlocking Blockchain's Potential in Supply Chain Management. Blockchain, 5(3), 34. https://www.mdpi.com/2673-8732/5/3/34
- Mubarak, A., & Smith, J. (2024). DIDChain: Advancing Supply Chain Data Management with Decentralized Identifiers and Blockchain. ResearchGate. https://www.researchgate.net/publication/381485655
- Androulaki, E., et al. (2018). Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains. EuroSys. https://dl.acm.org/doi/10.1145/3190508
- Zhang, R., & Liu, J. (2025). Implementing Identity Management and Access Control in Hyperledger Fabric for Industrial Supply Chains. Computer Science Review, 12(2), 145-160.
- McDonald, C. (2026). Mitigating Cybersecurity Risks in Decentralized Procurement. IT Supply Chain. https://itsupplychain.com
- NIST. (2018). Risk Management Framework for Information Systems (SP 800-37 Rev. 2). National Institute of Standards and Technology.
- W3C. (2022). Decentralized Identifiers (DIDs) v1.0 Core Architecture. W3C Recommendation. https://www.w3.org/TR/did-core/
- Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System. https://bitcoin.org/bitcoin.pdf
- Szabo, N. (1997). Formalizing and Securing Relationships on Public Networks. First Monday, 2(9).
- Buterin, V. (2014). Ethereum: A Next-Generation Smart Contract and Decentralized Application Platform. Ethereum White Paper.
- Reed, D., et al. (2020). Decentralized Identifiers: Implications for Your Data, Payments and Communications. IEEE Communications Standards Magazine.
- Xu, X., et al. (2019). The Blockchain as a Software Connector. IEEE International Conference on Software Architecture.
- Zheng, Z., et al. (2018). Blockchain Challenges and Opportunities: A Survey. International Journal of Web and Grid Services, 14(4), 352-375.
- Casino, F., Dasaklis, T. K., & Patsakis, C. (2019). A Systematic Literature Review of Blockchain-Based Applications. Telematics and Informatics, 36, 55-70.
- Kshetri, N. (2018). Blockchain's Roles in Meeting Key Supply Chain Management Objectives. International Journal of Information Management, 39, 80-89.
- Tian, F. (2016). An Agri-food Supply Chain Traceability System for China Based on RFID & Blockchain Technology. IEEE ICSSSM.
- Lacity, M. C. (2018). Addressing Key Challenges to Making Enterprise Blockchain Applications a Reality. MIS Quarterly Executive, 17(3).
- Saberi, S., et al. (2019). Blockchain Technology and Its Relationships to Sustainable Supply Chain Management. International Journal of Production Research, 57(7), 2117-2135.
