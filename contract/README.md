# HXRDomain Smart Contract

## Overview

The `HXRDomain` smart contract is designed to manage `.hxr` domains on the Hedera network. This contract supports the registration, renewal, transfer, and management of domains. It also includes functionalities to set DNS records, associate wallet addresses, and link IPFS hashes to domains.

## Features

- **Domain Registration**: Users can register `.hxr` domains.
- **Domain Renewal**: Domains can be renewed annually.
- **Domain Transfer**: Ownership of domains can be transferred.
- **DNS Management**: Set and remove DNS records for domains.
- **Wallet Address Association**: Link a Hedera wallet address to a domain.
- **IPFS Hash Association**: Link an IPFS hash to a domain.
- **Domain Suspension and Deletion**: Admin can suspend or delete domains.
- **Platform Authorization**: Authorize platforms for domain registration.
- **Blacklist Management**: Add or remove addresses from the blacklist.
- **Domain Sales**: List domains for sale and handle purchases.

## Requirements

- Solidity version `^0.8.0`
- Hedera Network
- Pyth Oracle for price feed
- OpenZeppelin contracts for security and utility

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rubixvi/hxr-smart-contract
   ```
2. Navigate to the project directory:
   ```bash
   cd hxr-smart-contract
   ```
3. Install the dependencies:
   ```bash
   npm install
   ```

## Usage

### Deployment

- **pythAddress:** The address of the Pyth oracle (Hedera: 0xA2aa501b19aff244D90cc15a4Cf739D2725B5729 (Main Net) | 0xa2aa501b19aff244d90cc15a4cf739d2725b5729 (Test Net) )
- **_hbarUSDPriceID** The price ID for HBAR/USD (HBAR/USD: 0x3728e591097635310e6341af53db8b7ee42da9b3a8d918f9463ce9cca886dfbd)
- **initialDomainPriceUSD** The initial domain price in USD
- **initialRenewalPriceUSD** The initial renewal price in USD
- **initialPlatformFeeUSD** The initial platform fee in USD
     
1. Deploy the contract using your preferred method (Remix, Truffle, Hardhat, etc.). Ensure to provide the required parameters during initialization:
   ```solidity
   address pythAddress,
   bytes32 _hbarUSDPriceID,
   uint256 initialDomainPriceUSD,
   uint256 initialRenewalPriceUSD,
   uint256 initialPlatformFeeUSD
   ```

2. Example initialization:
   ```javascript
   const HXRDomain = await HXRDomain.new(
       "0xA2aa501b19aff244D90cc15a4Cf739D2725B5729",
       "0x3728e591097635310e6341af53db8b7ee42da9b3a8d918f9463ce9cca886dfbd",
       15,
       15,
       1
   );
   ```

### Interactions

- **Register a Domain**:
  ```javascript
  await hxrDomain.registerDomain("example.hxr", { from: userAddress, value: registrationFee });
  ```

- **Renew a Domain**:
  ```javascript
  await hxrDomain.renewDomain("example.hxr", { from: userAddress, value: renewalFee });
  ```

- **Transfer a Domain**:
  ```javascript
  await hxrDomain.transferDomain("example.hxr", newOwnerAddress, { from: userAddress });
  ```

- **Set a DNS Record**:
  ```javascript
  await hxrDomain.setDnsRecord("example.hxr", "A", "192.168.1.1", { from: userAddress });
  ```

- **Set Wallet Address**:
  ```javascript
  await hxrDomain.setWalletAddress("example.hxr", "0.0.1234", { from: userAddress });
  ```

- **Set IPFS Hash**:
  ```javascript
  await hxrDomain.setIpfsHash("example.hxr", "QmHash", { from: userAddress });
  ```

- **List Domain for Sale**:
  ```javascript
  await hxrDomain.listDomainForSale("example.hxr", salePrice, { from: userAddress });
  ```

- **Purchase a Domain**:
  ```javascript
  await hxrDomain.purchaseDomain("example.hxr", { from: buyerAddress, value: salePrice });
  ```

## Events

- `DomainRegistered(string indexed domain, address indexed owner, uint256 expiry)`
- `DomainRenewed(string indexed domain, uint256 newExpiry)`
- `DomainTransferred(string indexed domain, address indexed oldOwner, address indexed newOwner)`
- `DnsRecordSet(string indexed domain, string recordType, string value)`
- `WalletAddressSet(string indexed domain, string walletAddress)`
- `IpfsHashSet(string indexed domain, string ipfsHash)`
- `DomainDeleted(string indexed domain)`
- `DomainSuspended(string indexed domain)`
- `DomainUnsuspended(string indexed domain)`
- `ContractInitialized(address pythAddress, bytes32 hbarUSDPriceID, uint256 domainPriceUSD, uint256 renewalPriceUSD, uint256 platformFeeUSD)`
- `DomainListedForSale(string indexed domain, address indexed seller, uint256 price)`
- `DomainSaleCancelled(string indexed domain, address indexed seller)`
- `DomainPurchased(string indexed domain, address indexed buyer, address indexed seller, uint256 price)`

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
