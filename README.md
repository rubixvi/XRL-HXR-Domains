# HXR Hedera Decentralised Domain (Smart Contract)

## Overview

HXR is a decentralized platform for managing `.hxr` domains using the Hedera network. The platform consists of four main components:

- **Client**: The frontend interface for users to interact with the domain management services.
- **Admin**: The administrative interface for managing the platform and its users.
- **Server**: The backend server that handles requests and communicates with the smart contract.
- **Contract**: The smart contract deployed on the Hedera network that controls domain registration, renewal, transfer, and DNS records.

## Smart Contract

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

## Getting Started

To get started with the HXR platform, you can clone the repository and start working on the client, admin, and server components. The smart contract is already provided and can be deployed to the Hedera network.

### Prerequisites

- Node.js
- npm or yarn
- Solidity compiler

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/rubixvi/HXR.git
   cd HXR
   ```

2. Install dependencies for each component (client, admin, server):

   ```sh
   cd client
   npm install
   cd ../admin
   npm install
   cd ../server
   npm install
   ```

### Usage

- **Client**: The client application for users to register and manage their `.hxr` domains.
- **Admin**: The administrative panel for managing the platform.
- **Server**: The backend server for handling requests and interacting with the smart contract.

### Deploying the Smart Contract

To deploy the smart contract, you need to have a Hedera account and the required tools to deploy smart contracts on the Hedera network.

1. Compile the smart contract using the Solidity compiler.
2. Deploy the compiled contract to the Hedera network.
3. Update the client and server configurations to interact with the deployed contract.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any improvements or new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

This `README.md` provides a comprehensive overview of your project, instructions for getting started, and details about the smart contract. You can modify it further as the project develops and additional components are added.