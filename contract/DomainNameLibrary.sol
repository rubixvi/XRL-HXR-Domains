// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library DomainNameLibrary {
    function validateDomain(string memory domain) internal pure returns (bool) {
        bytes memory domainBytes = bytes(domain);
        if (domainBytes.length < 3 || domainBytes.length > 253) {
            return false;
        }

        // Split the domain into labels
        uint labelLength = 0;
        bool lastWasHyphen = false;
        for (uint i = 0; i < domainBytes.length; i++) {
            bytes1 char = domainBytes[i];
            if (char == 0x2E) { // '.'
                if (labelLength == 0 || labelLength > 63) {
                    return false;
                }
                labelLength = 0;
                lastWasHyphen = false;
            } else {
                if (
                    !(char >= 0x30 && char <= 0x39) && // 0-9
                    !(char >= 0x41 && char <= 0x5A) && // A-Z
                    !(char >= 0x61 && char <= 0x7A) && // a-z
                    !(char == 0x2D) // -
                ) {
                    return false;
                }
                if (char == 0x2D) {
                    if (lastWasHyphen) {
                        return false;
                    }
                    lastWasHyphen = true;
                } else {
                    lastWasHyphen = false;
                }
                labelLength++;
            }
        }
        if (labelLength == 0 || labelLength > 63) {
            return false;
        }
        if (domainBytes[0] == 0x2D || domainBytes[domainBytes.length - 1] == 0x2D || domainBytes[domainBytes.length - 2] == 0x2E) {
            return false; // Domain name cannot start or end with a hyphen, or have a hyphen before the final dot
        }
        return true;
    }
}
