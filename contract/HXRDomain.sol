// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@pythnetwork/pyth-sdk-solidity/IPyth.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "./DomainNameLibrary.sol";

/**
 * @title HXRDomain
 * @dev Smart contract for managing .hxr domains, including registration, renewal, transfer, and DNS records.
 */
contract HXRDomain is ReentrancyGuard, Initializable {
    using Strings for uint256;
    using Strings for bytes32;
    using SafeCast for uint256;
    using DomainNameLibrary for string;

    address public admin; // Address of the contract admin
    uint256 public domainPriceUSD; // Price for domain registration in USD
    uint256 public renewalPriceUSD; // Price for domain renewal in USD
    uint256 public platformFeeUSD; // Platform fee in USD
    uint256 public constant GRACE_PERIOD = 30 days; // Grace period for domain renewal
    uint256 public constant ONE_YEAR = 365 days; // Duration for one year in seconds
    IPyth public pyth; // Pyth Network Oracle interface
    bytes32 public hbarUSDPriceID; // Pyth HBAR/USD price ID

    mapping(address => uint256) public lastAction; // Rate limiting mechanism

    // Struct representing a DNS record
    struct DnsRecord {
        string recordType; // Type of the DNS record
        string value; // Value of the DNS record
    }

    // Struct representing a domain
    struct Domain {
        address owner; // Owner of the domain
        uint256 expiry; // Expiry timestamp of the domain
        DnsRecord[] dnsRecords; // DNS records for the domain
        string walletAddress; // Wallet address associated with the domain
        string ipfsHash; // IPFS hash associated with the domain
        bool suspended; // Suspension status of the domain
    }

    // Struct representing a domain sale
    struct DomainSale {
        address seller; // Seller of the domain
        uint256 price; // Sale price of the domain
        bool active; // Status of the domain sale
    }

    mapping(string => Domain) public domains; // Mapping from domain name to Domain struct
    mapping(string => DomainSale) public domainSales; // Mapping from domain name to DomainSale struct
    mapping(address => bool) public authorizedPlatforms; // Authorized platforms for domain registration
    mapping(address => bool) public blacklistedAddresses; // Blacklisted addresses

    // Events for domain actions
    event DomainRegistered(string indexed domain, address indexed owner, uint256 expiry);
    event DomainRenewed(string indexed domain, uint256 newExpiry);
    event DomainTransferred(string indexed domain, address indexed oldOwner, address indexed newOwner);
    event DnsRecordSet(string indexed domain, string recordType, string value);
    event WalletAddressSet(string indexed domain, string walletAddress);
    event IpfsHashSet(string indexed domain, string ipfsHash);
    event DomainDeleted(string indexed domain);
    event DomainSuspended(string indexed domain);
    event DomainUnsuspended(string indexed domain);
    event TransferFailed(address indexed to, uint256 amount);
    event ContractInitialized(address pythAddress, bytes32 hbarUSDPriceID, uint256 domainPriceUSD, uint256 renewalPriceUSD, uint256 platformFeeUSD);
    event DomainListedForSale(string indexed domain, address indexed seller, uint256 price);
    event DomainSaleCancelled(string indexed domain, address indexed seller);
    event DomainPurchased(string indexed domain, address indexed buyer, address indexed seller, uint256 price);

    // Modifiers for function access control
    modifier onlyAdmin() {
        require(msg.sender == admin, "HXRDomain: Only admin can perform this action");
        _;
    }

    modifier onlyOwner(string memory domain) {
        require(domains[domain].owner == msg.sender, "HXRDomain: Only the domain owner can perform this action");
        _;
    }

    modifier notBlacklisted(address userAddress) {
        require(!blacklistedAddresses[userAddress], "HXRDomain: Address is blacklisted");
        _;
    }

    modifier domainNotExpired(string memory domain) {
        require(domains[domain].expiry > block.timestamp, "HXRDomain: Domain is expired");
        _;
    }

    modifier domainNotSuspended(string memory domain) {
        require(!domains[domain].suspended, "HXRDomain: Domain is suspended");
        _;
    }

    modifier rateLimited(address userAddress) {
        require(block.timestamp > lastAction[userAddress] + 1 minutes, "HXRDomain: Rate limit exceeded");
        _;
    }

    /**
     * @dev Initializes the contract with key parameters
     * @param pythAddress The address of the Pyth oracle
     * @param _hbarUSDPriceID The price ID for HBAR/USD
     * @param initialDomainPriceUSD The initial domain price in USD
     * @param initialRenewalPriceUSD The initial renewal price in USD
     * @param initialPlatformFeeUSD The initial platform fee in USD
     */
    function initialize(
        address pythAddress,
        bytes32 _hbarUSDPriceID,
        uint256 initialDomainPriceUSD,
        uint256 initialRenewalPriceUSD,
        uint256 initialPlatformFeeUSD
    ) public initializer {
        require(pythAddress != address(0), "HXRDomain: Invalid Pyth address");
        require(_hbarUSDPriceID != bytes32(0), "HXRDomain: Invalid price ID");
        require(initialDomainPriceUSD > 0, "HXRDomain: Domain price must be greater than zero");
        require(initialRenewalPriceUSD > 0, "HXRDomain: Renewal price must be greater than zero");
        require(initialPlatformFeeUSD > 0, "HXRDomain: Platform fee must be greater than zero");

        admin = msg.sender;
        pyth = IPyth(pythAddress);
        hbarUSDPriceID = _hbarUSDPriceID;
        domainPriceUSD = initialDomainPriceUSD;
        renewalPriceUSD = initialRenewalPriceUSD;
        platformFeeUSD = initialPlatformFeeUSD;

        // Emit an event to notify users of contract initialization
        emit ContractInitialized(pythAddress, _hbarUSDPriceID, initialDomainPriceUSD, initialRenewalPriceUSD, initialPlatformFeeUSD);
    }

    /**
     * @dev Authorize a platform for domain registration.
     * @param platform Address of the platform to be authorized
     */
    function authorizePlatform(address platform) external onlyAdmin {
        require(platform != address(0), "HXRDomain: Invalid platform address");
        authorizedPlatforms[platform] = true;
    }

    /**
     * @dev Revoke a platform's authorization.
     * @param platform Address of the platform to be revoked
     */
    function revokePlatform(address platform) external onlyAdmin {
        require(platform != address(0), "HXRDomain: Invalid platform address");
        authorizedPlatforms[platform] = false;
    }

    /**
     * @dev Add an address to the blacklist.
     * @param userAddress Address to be blacklisted
     */
    function blacklistAddress(address userAddress) external onlyAdmin {
        require(userAddress != address(0), "HXRDomain: Invalid address");
        blacklistedAddresses[userAddress] = true;
    }

    /**
     * @dev Remove an address from the blacklist.
     * @param userAddress Address to be removed from the blacklist
     */
    function removeBlacklistAddress(address userAddress) external onlyAdmin {
        require(userAddress != address(0), "HXRDomain: Invalid address");
        blacklistedAddresses[userAddress] = false;
    }

    /**
     * @dev Get the latest price of HBAR in USD from the Pyth Oracle.
     * @return The latest price of HBAR in USD
     */
    function getLatestPrice() public view returns (uint256) {
        PythStructs.Price memory price = pyth.getPrice(hbarUSDPriceID);
        uint256 hbarPrice = (uint256(int256(price.price)) * (10 ** 8)) / (10 ** uint32(-1 * price.expo));
        return hbarPrice;
    }

    /**
     * @dev Convert an amount in USD to HBAR based on the latest price.
     * @param amountInUSD The amount in USD to be converted
     * @return The equivalent amount in HBAR
     */
    function usdToHbar(uint256 amountInUSD) public view returns (uint256) {
        uint256 hbarPrice = getLatestPrice();
        uint256 amountInHbar = (amountInUSD * 10 ** 8) / hbarPrice;
        return amountInHbar;
    }

    /**
     * @dev Register a new domain.
     * @param domain The name of the domain to be registered
     */
    function registerDomain(string memory domain) external payable notBlacklisted(msg.sender) rateLimited(msg.sender) nonReentrant {
        require(authorizedPlatforms[msg.sender], "HXRDomain: Platform not authorized");
        require(domains[domain].owner == address(0), "HXRDomain: Domain already registered");
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        uint256 requiredAmount = usdToHbar(domainPriceUSD + platformFeeUSD);
        require(msg.value >= requiredAmount, "HXRDomain: Insufficient funds");

        domains[domain].owner = msg.sender;
        domains[domain].expiry = block.timestamp + ONE_YEAR;

        // Transfer the fee to the admin
        uint256 feeAmount = usdToHbar(platformFeeUSD);
        if (address(this).balance >= feeAmount) {
            payable(admin).transfer(feeAmount);
        } else {
            emit TransferFailed(admin, feeAmount);
        }

        emit DomainRegistered(domain, msg.sender, domains[domain].expiry);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Renew an existing domain.
     * @param domain The name of the domain to be renewed
     */
    function renewDomain(string memory domain) external payable onlyOwner(domain) notBlacklisted(msg.sender) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        uint256 requiredAmount = usdToHbar(renewalPriceUSD + platformFeeUSD);
        require(msg.value >= requiredAmount, "HXRDomain: Insufficient funds");

        require(
            domains[domain].expiry > block.timestamp || 
            (domains[domain].expiry + GRACE_PERIOD > block.timestamp),
            "HXRDomain: Domain expired and grace period over"
        );

        if (domains[domain].expiry < block.timestamp) {
            // Domain is within grace period
            domains[domain].expiry = block.timestamp + ONE_YEAR;
        } else {
            // Domain is not expired
            domains[domain].expiry += ONE_YEAR;
        }

        // Transfer the fee to the admin
        uint256 feeAmount = usdToHbar(platformFeeUSD);
        if (address(this).balance >= feeAmount) {
            payable(admin).transfer(feeAmount);
        } else {
            emit TransferFailed(admin, feeAmount);
        }

        emit DomainRenewed(domain, domains[domain].expiry);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can renew a domain.
     * @param domain The name of the domain to be renewed
     */
    function adminRenewDomain(string memory domain) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        
        domains[domain].expiry += ONE_YEAR;

        emit DomainRenewed(domain, domains[domain].expiry);
    }

    /**
     * @dev Transfer a domain to a new owner.
     * @param domain The name of the domain to be transferred
     * @param newOwner The address of the new owner
     */
    function transferDomain(string memory domain, address newOwner) external onlyOwner(domain) notBlacklisted(newOwner) domainNotSuspended(domain) domainNotExpired(domain) rateLimited(msg.sender) nonReentrant {
        require(newOwner != address(0), "HXRDomain: Invalid new owner address");
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        
        domains[domain].owner = newOwner;

        emit DomainTransferred(domain, msg.sender, newOwner);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can transfer a domain to a new owner.
     * @param domain The name of the domain to be transferred
     * @param newOwner The address of the new owner
     */
    function adminTransferDomain(string memory domain, address newOwner) external onlyAdmin notBlacklisted(newOwner) domainNotExpired(domain) nonReentrant {
        require(newOwner != address(0), "HXRDomain: Invalid new owner address");
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        address oldOwner = domains[domain].owner;
        domains[domain].owner = newOwner;

        emit DomainTransferred(domain, oldOwner, newOwner);
    }

    /**
     * @dev Set a DNS record for a domain.
     * @param domain The name of the domain
     * @param recordType The type of the DNS record (e.g., A, CNAME)
     * @param value The value of the DNS record
     */
    function setDnsRecord(string memory domain, string memory recordType, string memory value) external onlyOwner(domain) domainNotExpired(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateDnsRecord(recordType, value), "HXRDomain: Invalid DNS record");

        domains[domain].dnsRecords.push(DnsRecord(recordType, value));

        emit DnsRecordSet(domain, recordType, value);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can set a DNS record for a domain.
     * @param domain The name of the domain
     * @param recordType The type of the DNS record (e.g., A, CNAME)
     * @param value The value of the DNS record
     */
    function adminSetDnsRecord(string memory domain, string memory recordType, string memory value) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateDnsRecord(recordType, value), "HXRDomain: Invalid DNS record");

        domains[domain].dnsRecords.push(DnsRecord(recordType, value));

        emit DnsRecordSet(domain, recordType, value);
    }

    /**
     * @dev Remove a DNS record for a domain.
     * @param domain The name of the domain
     * @param recordType The type of the DNS record to be removed
     * @param value The value of the DNS record to be removed
     */
    function removeDnsRecord(string memory domain, string memory recordType, string memory value) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        DnsRecord[] storage records = domains[domain].dnsRecords;
        for (uint i = 0; i < records.length; i++) {
            if (keccak256(bytes(records[i].recordType)) == keccak256(bytes(recordType)) && keccak256(bytes(records[i].value)) == keccak256(bytes(value))) {
                records[i] = records[records.length - 1];
                records.pop();
                emit DnsRecordSet(domain, recordType, "");
                break;
            }
        }

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can remove a DNS record for a domain.
     * @param domain The name of the domain
     * @param recordType The type of the DNS record to be removed
     * @param value The value of the DNS record to be removed
     */
    function adminRemoveDnsRecord(string memory domain, string memory recordType, string memory value) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        DnsRecord[] storage records = domains[domain].dnsRecords;
        for (uint i = 0; i < records.length; i++) {
            if (keccak256(bytes(records[i].recordType)) == keccak256(bytes(recordType)) && keccak256(bytes(records[i].value)) == keccak256(bytes(value))) {
                records[i] = records[records.length - 1];
                records.pop();
                emit DnsRecordSet(domain, recordType, "");
                break;
            }
        }
    }

    /**
     * @dev Set a wallet address for a domain.
     * @param domain The name of the domain
     * @param walletAddress The wallet address to be set
     */
    function setWalletAddress(string memory domain, string memory walletAddress) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateWalletAddress(walletAddress), "HXRDomain: Invalid wallet address");

        domains[domain].walletAddress = walletAddress;
        emit WalletAddressSet(domain, walletAddress);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can set a wallet address for a domain.
     * @param domain The name of the domain
     * @param walletAddress The wallet address to be set
     */
    function adminSetWalletAddress(string memory domain, string memory walletAddress) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateWalletAddress(walletAddress), "HXRDomain: Invalid wallet address");

        domains[domain].walletAddress = walletAddress;
        emit WalletAddressSet(domain, walletAddress);
    }

    /**
     * @dev Remove the wallet address associated with a domain.
     * @param domain The name of the domain
     */
    function removeWalletAddress(string memory domain) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        delete domains[domain].walletAddress;
        emit WalletAddressSet(domain, "");

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can remove the wallet address associated with a domain.
     * @param domain The name of the domain
     */
    function adminRemoveWalletAddress(string memory domain) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        delete domains[domain].walletAddress;
        emit WalletAddressSet(domain, "");
    }

    /**
     * @dev Set an IPFS hash for a domain.
     * @param domain The name of the domain
     * @param ipfsHash The IPFS hash to be set
     */
    function setIpfsHash(string memory domain, string memory ipfsHash) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateIpfsHash(ipfsHash), "HXRDomain: Invalid IPFS hash");

        domains[domain].ipfsHash = ipfsHash;
        emit IpfsHashSet(domain, ipfsHash);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can set an IPFS hash for a domain.
     * @param domain The name of the domain
     * @param ipfsHash The IPFS hash to be set
     */
    function adminSetIpfsHash(string memory domain, string memory ipfsHash) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        require(validateIpfsHash(ipfsHash), "HXRDomain: Invalid IPFS hash");

        domains[domain].ipfsHash = ipfsHash;
        emit IpfsHashSet(domain, ipfsHash);
    }

    /**
     * @dev Remove the IPFS hash associated with a domain.
     * @param domain The name of the domain
     */
    function removeIpfsHash(string memory domain) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        delete domains[domain].ipfsHash;
        emit IpfsHashSet(domain, "");

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Admin can remove the IPFS hash associated with a domain.
     * @param domain The name of the domain
     */
    function adminRemoveIpfsHash(string memory domain) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        delete domains[domain].ipfsHash;
        emit IpfsHashSet(domain, "");
    }

    /**
     * @dev Get the wallet address associated with a domain.
     * @param domain The name of the domain
     * @return The wallet address associated with the domain
     */
    function getWalletAddress(string memory domain) external view onlyOwner(domain) returns (string memory) {
        return domains[domain].walletAddress;
    }

    /**
     * @dev Get a DNS record for a domain.
     * @param domain The name of the domain
     * @param recordType The type of the DNS record
     * @return The value of the DNS record
     */
    function getDnsRecord(string memory domain, string memory recordType) external view onlyOwner(domain) returns (string memory) {
        for (uint i = 0; i < domains[domain].dnsRecords.length; i++) {
            if (keccak256(bytes(domains[domain].dnsRecords[i].recordType)) == keccak256(bytes(recordType))) {
                return domains[domain].dnsRecords[i].value;
            }
        }
        return "";
    }

    /**
     * @dev Get the IPFS hash associated with a domain.
     * @param domain The name of the domain
     * @return The IPFS hash associated with the domain
     */
    function getIpfsHash(string memory domain) external view onlyOwner(domain) returns (string memory) {
        return domains[domain].ipfsHash;
    }

    /**
     * @dev Get the platform fee.
     * @return The platform fee
     */
    function getPlatformFee() public view returns (uint256) {
        return platformFeeUSD;
    }

    /**
     * @dev Suspend a domain.
     * @param domain The name of the domain to be suspended
     */
    function suspendDomain(string memory domain) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");
        
        domains[domain].suspended = true;

        emit DomainSuspended(domain);
    }

    /**
     * @dev Unsuspend a domain.
     * @param domain The name of the domain to be unsuspended
     */
    function unsuspendDomain(string memory domain) external onlyAdmin nonReentrant {
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        domains[domain].suspended = false;

        emit DomainUnsuspended(domain);
    }

    /**
     * @dev Delete a domain.
     * @param domain The name of the domain to be deleted
     */
    function deleteDomain(string memory domain) external onlyAdmin nonReentrant {
        require(domains[domain].owner != address(0), "HXRDomain: Domain not found");
        require(domain.validateDomain(), "HXRDomain: Invalid domain name");

        delete domains[domain];
        emit DomainDeleted(domain);
    }

    /**
     * @dev Withdraw the contract balance to the admin address.
     */
    function withdraw() external onlyAdmin nonReentrant {
        (bool success, ) = admin.call{value: address(this).balance}("");
        require(success, "HXRDomain: Withdraw failed");
    }

    /**
     * @dev Receive function for handling plain HBAR transfers.
     */
    receive() external payable {
        revert("HXRDomain: Direct payments not allowed");
    }

    /**
     * @dev Update the Pyth price feed address and HBAR/USD price ID.
     * @param newPythAddress The address of the new Pyth price feed
     * @param newHbarUSDPriceID The new HBAR/USD price ID
     */
    function updatePyth(address newPythAddress, bytes32 newHbarUSDPriceID) external onlyAdmin {
        require(newPythAddress != address(0), "HXRDomain: Invalid Pyth address");
        require(newHbarUSDPriceID != bytes32(0), "HXRDomain: Invalid price ID");
        pyth = IPyth(newPythAddress);
        hbarUSDPriceID = newHbarUSDPriceID;
    }

    /**
     * @dev Validate a DNS record.
     * @param recordType The type of the DNS record
     * @param value The value of the DNS record
     * @return True if the DNS record is valid, otherwise false
     */
    function validateDnsRecord(string memory recordType, string memory value) internal pure returns (bool) {
        bytes memory recordTypeBytes = bytes(recordType);
        bytes memory valueBytes = bytes(value);
        if (recordTypeBytes.length == 0 || valueBytes.length == 0) {
            return false;
        }
        // Additional validation: Ensure record type and value contain only valid characters
        for (uint i = 0; i < recordTypeBytes.length; i++) {
            bytes1 char = recordTypeBytes[i];
            if (
                !(char >= 0x30 && char <= 0x39) && // 0-9
                !(char >= 0x41 && char <= 0x5A) && // A-Z
                !(char >= 0x61 && char <= 0x7A) && // a-z
                !(char == 0x2D) // -
            ) {
                return false;
            }
        }
        for (uint i = 0; i < valueBytes.length; i++) {
            bytes1 char = valueBytes[i];
            if (
                !(char >= 0x30 && char <= 0x39) && // 0-9
                !(char >= 0x41 && char <= 0x5A) && // A-Z
                !(char >= 0x61 && char <= 0x7A) && // a-z
                !(char == 0x2D || char == 0x2E || char == 0x3A || char == 0x2F) // - . : /
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Validate a wallet address.
     * @param walletAddress The wallet address to be validated
     * @return True if the wallet address is valid, otherwise false
     */
    function validateWalletAddress(string memory walletAddress) internal pure returns (bool) {
        return validateHederaAccountId(walletAddress);
    }

    /**
     * @dev Validate an IPFS hash.
     * @param ipfsHash The IPFS hash to be validated
     * @return True if the IPFS hash is valid, otherwise false
     */
    function validateIpfsHash(string memory ipfsHash) internal pure returns (bool) {
        bytes memory hashBytes = bytes(ipfsHash);
        if (hashBytes.length != 46 || hashBytes[0] != 0x51) { // IPFS hashes start with "Qm"
            return false;
        }
        for (uint i = 1; i < hashBytes.length; i++) {
            bytes1 char = hashBytes[i];
            if (
                !(char >= 0x30 && char <= 0x39) && // 0-9
                !(char >= 0x41 && char <= 0x5A) && // A-Z
                !(char >= 0x61 && char <= 0x7A) // a-z
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Validate a Hedera account ID.
     * @param accountId The account ID to be validated
     * @return True if the account ID is valid, otherwise false
     */
    function validateHederaAccountId(string memory accountId) internal pure returns (bool) {
        // Split the string by '.'
        string[] memory parts = split(accountId, ".");

        // Check that there are exactly 3 parts and the first two parts are '0'
        if (parts.length != 3 || keccak256(bytes(parts[0])) != keccak256(bytes("0")) || keccak256(bytes(parts[1])) != keccak256(bytes("0"))) {
            return false;
        }

        // Check that the third part is a positive integer
        uint256 accountNumber = parseUint(parts[2]);
        if (accountNumber == 0 && keccak256(bytes(parts[2])) != keccak256(bytes("0"))) {
            return false;
        }

        return true;
    }

    /**
     * @dev Split a string into an array of substrings based on a delimiter.
     * @param s The string to be split
     * @param delim The delimiter character
     * @return An array of substrings
     */
    function split(string memory s, string memory delim) internal pure returns (string[] memory) {
        bytes memory b = bytes(s);
        bytes memory delimiter = bytes(delim);
        uint256 count = 1;
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == delimiter[0]) {
                count++;
            }
        }
        string[] memory parts = new string[](count);
        uint256 j = 0;
        uint256 start = 0;
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == delimiter[0]) {
                parts[j] = substring(s, start, i - start);
                start = i + 1;
                j++;
            }
        }
        parts[j] = substring(s, start, b.length - start);
        return parts;
    }

    /**
     * @dev Get a substring of a string.
     * @param str The original string
     * @param startIndex The start index of the substring
     * @param length The length of the substring
     * @return The substring
     */
    function substring(string memory str, uint256 startIndex, uint256 length) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = strBytes[startIndex + i];
        }
        return string(result);
    }

    /**
     * @dev Parse a string to an unsigned integer.
     * @param s The string to be parsed
     * @return The unsigned integer value
     */
    function parseUint(string memory s) internal pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint8 digit = uint8(b[i]) - 48;
            if (digit < 0 || digit > 9) {
                return 0;
            }
            result = result * 10 + digit;
        }
        return result;
    }

    /**
     * @dev List a domain for sale.
     * @param domain The name of the domain to be listed
     * @param price The price at which the domain is to be sold
     */
    function listDomainForSale(string memory domain, uint256 price) external onlyOwner(domain) domainNotExpired(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(price > 0, "HXRDomain: Price must be greater than zero");
        require(!domainSales[domain].active, "HXRDomain: Domain already listed for sale");

        domainSales[domain] = DomainSale(msg.sender, price, true);
        emit DomainListedForSale(domain, msg.sender, price);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Cancel a domain sale.
     * @param domain The name of the domain whose sale is to be cancelled
     */
    function cancelDomainSale(string memory domain) external onlyOwner(domain) domainNotSuspended(domain) rateLimited(msg.sender) nonReentrant {
        require(domainSales[domain].active, "HXRDomain: Domain not listed for sale");

        delete domainSales[domain];
        emit DomainSaleCancelled(domain, msg.sender);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }

    /**
     * @dev Purchase a domain listed for sale.
     * @param domain The name of the domain to be purchased
     */
    function purchaseDomain(string memory domain) external payable notBlacklisted(msg.sender) domainNotExpired(domain) rateLimited(msg.sender) nonReentrant {
        DomainSale storage sale = domainSales[domain];
        require(sale.active, "HXRDomain: Domain not listed for sale");
        require(msg.value >= sale.price, "HXRDomain: Insufficient funds");

        address seller = sale.seller;
        domains[domain].owner = msg.sender;
        sale.active = false;

        // Transfer the payment to the seller
        payable(seller).transfer(sale.price);

        emit DomainPurchased(domain, msg.sender, seller, sale.price);

        lastAction[msg.sender] = block.timestamp; // Update rate limiting
    }
}
