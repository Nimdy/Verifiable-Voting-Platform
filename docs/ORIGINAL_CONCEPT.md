# Original Concept (preserved for provenance)

> This is the **original** project README, preserved verbatim as the seed idea for what became
> the modernized platform described in the top-level [README](../README.md). It is kept here
> for history and because several of its instincts (a public bulletin board, a paper audit
> trail, single-use eligibility tokens, separating *who is eligible* from *how they voted*)
> map directly onto sound, modern constructions. The modern README documents which parts were
> kept, which were replaced, and why.

---

# Voting-Election-System Blockchain

## Blockchain Concept for Voting Election Systems

The voting process would initiate with the creation of a decentralized ledger on a blockchain network to record all votes in real-time. This ledger would be maintained by a network of nodes working collaboratively to ensure the integrity and security of the voting process.

### Voter Eligibility and Token System

To ensure that only eligible citizens can vote, states would issue tokens to U.S. citizens using their Social Security Number (SSN) as the basis. These tokens, called Social Security Tokens (SSTs), would be linked to the voter's identification documents, such as driver licenses, state IDs, or voting cards. This linkage would ensure that only registered citizens can access the voting process.

Upon registration, citizens would receive a Voter Enabled Token (VET), unique to each voter and linked to their SST. The VET would confirm the voter's identity and eligibility to vote.

#### Deregistration of Tokens

VETs could be deregistered for various reasons, such as death, renunciation of citizenship, or felony conviction. These invalidated tokens, known as DEREG-VETs, would no longer be valid for voting.

Similarly, SSTs could be deregistered upon death or renunciation of citizenship and placed into cold storage for historical tracking and census data, ensuring that only eligible citizens are active participants in the voting process.

### Validation and Fraud Prevention

States, counties, and districts would validate their Current Vote Eligible Persons (CVEP) by comparing the number of citizens to census data and the number of eligible voters (aged 18-120, excluding disqualifying factors like felony convictions). This process would help prevent voter fraud and ensure only eligible citizens can vote.

This system aims to provide a secure, transparent, and accurate voting process, preventing voter fraud and ensuring only eligible citizens participate.

## Anonymous Voting Process

To ensure anonymity and protect personal identity, the Voter Enabled Token (VET) could be combined with Scrambled Prime Key Encryption (SPKE) to create an Anonymous Activated Voter Enabled Token (AAVET).

The AAVET, unique to each voter, would be created by scrambling the voter's prime key (a unique identifier) with a randomly generated encryption key, making it difficult to trace a vote back to an individual voter.

The AAVET would be used to cast a vote on the blockchain-based voting system, with the vote recorded as a transaction on the blockchain. This additional layer of security and anonymity would require additional resources and complexity.

## Voting Process

1. Citizens register to vote.
2. Citizens visit voting centers.
3. Vote center clerks validate voter registration.
4. Citizens place their ID on an RFID Voting Process Unit (RFID-VPU) for processing.
5. The RFID-VPU detects the Voter Enabled Token (VET) and activates the Blank Reusable Voting Card (BRVC).
6. The RFID-VPU places the Anonymous Activated Voter Enabled Token (AAVET) on the BRVC.
7. The Voting Blockchain updates with a successful voting slot and awaits AAVET confirmation.
8. The voter is handed the BRVC.
9. The voter enters a booth and places the BRVC on the voting machine.
10. The voting machine establishes an encrypted connection to the Voting Blockchain.
11. The voter selects their desired vote(s).
12. The voting machine registers the vote(s) and asks for confirmation.
13. The voter reviews the vote(s) and confirms.
14. The voting machine updates the Voting Blockchain ledger and removes the AAVET from the BRVC.
15. The AAVET is locked into the Voting Blockchain slot and cannot be changed. The Blockchain slot is closed.
16. The Voting Blockchain ledger is updated.
17. The voter is provided confirmation and can see their vote listed within the Voting Blockchain.
18. The voting machine can print a paper ballot for the voter to turn in to the voting clerk for confirmation, audits, etc.
19. The AAVET is now useless for additional voting since it is no longer valid.
20. The voter removes the BRVC and leaves the booth.
21. The voter returns the BRVC for reissue to the next voter.
22. The vote clerk places the BRVC on the RFID Wipe Clean Verify System (RFID-WCVS).
23. The BRVC is issued to the next voter and the process repeats.
24. Voting statistics are displayed publicly for all to see.

## Security and Transparency Measures

- **Time-to-live (TTL) limits**: Prevents the AAVET from being used again after a certain period.
- **Multi-signature validation**: Requires multiple parties to sign off on a transaction before it is recorded on the blockchain.
- **Smart contract-based validation**: Self-executing contracts that confirm voter eligibility and vote validity.

### Additional Considerations for Security and Transparency

- **Voter education**: Provide resources and training for election officials.
- **Voter registration**: Secure and efficient, allowing voters to register once and vote in any location.
- **Voter turnout**: Increase turnout by making voting easier with convenient locations and early voting options.
- **Voter confidence**: Increase confidence with transparent processes and fraud prevention.
- **Technical support**: Reliable support system for technical issues.
- **Cost**: Weigh implementation and maintenance costs against benefits.
- **Interoperability**: Ensure smooth integration with other systems.
- **Compliance with regulations**: Follow all relevant laws and regulations.
- **Auditing**: Independent verification of voting results.
- **Voter-verified paper audit trail (VVPAT)**: Provide a paper trail for voter confirmation and audit purposes.
- **Accessibility**: Make voting accessible to all eligible voters.
- **Decentralization**: Utilize blockchain's decentralization for secure data storage.
- **Smart Contracts**: Automate the voting process to ensure transparency and security.
- **Anonymity**: Use techniques like zero-knowledge proofs for identity protection.
- **Security**: Implement robust security measures against cyber attacks.
- **Transparency**: Provide public access to the voting process and results.

## Priority Ranking

1. Voter confidence
2. Security
3. Transparency
4. Compliance with regulations
5. Voter turnout
6. Voter education
7. Voter registration
8. Auditing
9. Voter-verified paper audit trail (VVPAT)
10. Accessibility
11. Decentralization
12. Smart Contracts
13. Anonymity
14. Interoperability
15. Technical support
16. Cost-effectiveness

## High-Level Blockchain Network Representation

- **Nodes**: Multiple nodes maintaining the blockchain ledger in real-time.
- **Consensus Algorithm**: Proof of Stake (PoS) for consensus on ledger state.
- **API**: Integration with voting machines, RFID-VPUs, and related systems.
- **Smart Contracts**: Validate voter eligibility, enforce single voting, and count/report results.
- **SPKE**: Encrypt voter prime keys for AAVET creation.
- **TTL Mechanism**: Prevents reuse of AAVET after a set time.
- **VVPAT**: Physical vote copy for voter review and audit.
- **Public Access**: Real-time vote counting and result publication.

## Necessary Laws

1. **Voter identification laws**: Require government-issued IDs for voting.
2. **Election integrity laws**: Establish penalties for fraud, audit processes, and dispute resolution.
3. **Cybersecurity laws**: Set standards for voting system security and incident response.
4. **Privacy laws**: Protect voter personal information and resolve privacy disputes.
5. **Blockchain laws**: Govern the use of blockchain technology in voting.

## Pilot Testing

Testing the blockchain-based voting system on a smaller scale, such as city council or mayoral elections, would demonstrate its benefits:

- **Feasibility**: Identify and solve technical issues.
- **Security**: Identify and address vulnerabilities.
- **Transparency**: Ensure a clear voting process.
- **Voter acceptance**: Improve user experience and accessibility.
- **Legal compliance**: Identify and address regulatory issues.
- **Cost-effectiveness**: Evaluate costs and benefits.

Smaller-scale tests would provide valuable feedback from stakeholders, demonstrating the system's transparency and security benefits, increasing public trust, and showcasing the advantages of smart contracts.

## Acronyms

- **AAVET**: Anonymous Activated Voter Enabled Token
- **BRVC**: Blank Reusable Voting Card
- **CC**: Citizen Count
- **CD**: Census Data
- **CVEP**: Current Vote Eligible Persons
- **DEREG-VET**: De-registered Voter Enabled Token
- **RFID-VPU**: RFID Voting Process Unit
- **RFID-WCVS**: RFID Wipe Clean Verify System
- **SST**: Social Security Token
- **SPKE**: Scrambled Prime Key Encryption
- **VEP**: Vote Eligible Persons
- **VET**: Voter Enabled Token

## Final Thoughts

This blockchain-based voting system design envisions a perfect world where the technology is fully developed, tested, and implemented to its full potential. It aims to provide a secure, transparent, and accurate voting process, increasing voter turnout and public trust. While this idea requires extensive research, development, and compliance with laws, it represents a proactive approach to solving current voting system issues. Even small contributions can drive significant progress, so it's essential to keep innovating and striving for improvements.

;)
