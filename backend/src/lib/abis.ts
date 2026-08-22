// ABI definitions for Q-Trust contracts (generated from Forge artifacts).
// Regenerate: python3 scripts/generate_abis.py --target ts

export const AssetRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "EIP712_VERSION_HASH",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "REGISTRAR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "assetCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "domainSeparator",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAllAssetIds",
      inputs: [
            {
                  name: "offset",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "limit",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "page",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
            {
                  name: "total",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAsset",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct AssetRegistry.Asset",
                  components: [
                        {
                              name: "orgDid",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "cbomHash",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "metadataURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "lastUpdated",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAssetsByOrg",
      inputs: [
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "hashTypedCBOMRegistration",
      inputs: [
            {
                  name: "cbomHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "nonces",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "registerCBOM",
      inputs: [
            {
                  name: "cbomHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "registerCBOMSigned",
      inputs: [
            {
                  name: "cbomHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "signature",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "retireAsset",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "updateCBOM",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "newCbomHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "newMetadataURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "verifyAsset",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "exists",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "active",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "event",
      name: "CBOMRegistered",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "orgDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "cbomHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "CBOMRetired",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "CBOMUpdated",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newCbomHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "newMetadataURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "AssetAlreadyExists",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AssetAlreadyRetired",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AssetNotFound",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureLength",
      inputs: [
            {
                  name: "length",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureS",
      inputs: [
            {
                  name: "s",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyHash",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidNonce",
      inputs: [
            {
                  name: "signer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "provided",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "expected",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "InvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "MetadataTooLong",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "NotRegistrar",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export const VendorRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "EIP712_VERSION_HASH",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "MAX_ATTESTATIONS_PER_PRODUCT",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "VENDOR_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "VENDOR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "attestProduct",
      inputs: [
            {
                  name: "productId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "supported",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "attestProductSigned",
      inputs: [
            {
                  name: "productId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "supported",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "signature",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "checkProductSupport",
      inputs: [
            {
                  name: "productId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "supported",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "deactivateVendor",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "domainSeparator",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAttestation",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct VendorRegistry.ProductAttestation",
                  components: [
                        {
                              name: "vendorDid",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "productId",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "version",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "algorithm",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "supported",
                              type: "bool",
                              internalType: "bool",
                            },
                        {
                              name: "evidenceURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "revoked",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAttestationsByProduct",
      inputs: [
            {
                  name: "productId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAttestationsByVendor",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getVendor",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct VendorRegistry.VendorInfo",
                  components: [
                        {
                              name: "name",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "metadataURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "registeredAt",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "hashTypedAttestation",
      inputs: [
            {
                  name: "productId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "supported",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "isVendorActive",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "nonces",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "registerVendor",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "name",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeAttestation",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "event",
      name: "AttestationRevoked",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "ProductAttested",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "vendorDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "productId",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "algorithm",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "supported",
                  type: "bool",
                  indexed: false,
                  internalType: "bool",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "VendorDeactivated",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "VendorRegistered",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "name",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "metadataURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "AttestationLimitExceeded",
      inputs: [
            {
                  name: "productIdHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AttestationNotFound",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "DuplicateAttestation",
      inputs: [
            {
                  name: "attestationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureLength",
      inputs: [
            {
                  name: "length",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureS",
      inputs: [
            {
                  name: "s",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidNonce",
      inputs: [
            {
                  name: "signer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "provided",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "expected",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "InvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "NotVendor",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "VendorAlreadyRegistered",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "VendorInactive",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "VendorNotFound",
      inputs: [
            {
                  name: "vendorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
    }
] as const;

export const MigrationRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "AUDITOR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "EIP712_VERSION_HASH",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "MIGRATOR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "assetRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract AssetRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "domainSeparator",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getMigration",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct MigrationRegistry.Migration",
                  components: [
                        {
                              name: "assetId",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "orgDid",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "fromAlgorithm",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "toAlgorithm",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "evidenceHash",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "evidenceURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "verified",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getMigrationsByAsset",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getMigrationsByOrg",
      inputs: [
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "hashTypedMigration",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "fromAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "toAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "evidenceHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [
            {
                  name: "assetRegistry_",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "migrationCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "nonces",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "recordMigration",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "fromAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "toAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "evidenceHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "recordedMigrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "recordMigrationSigned",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "fromAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "toAlgorithm",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "evidenceHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "signature",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "recordedMigrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "verifyMigration",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "MigrationRecorded",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "assetId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "orgDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "fromAlgorithm",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "toAlgorithm",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "evidenceHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "evidenceURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "AssetInactive",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AssetNotRegistered",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "DuplicateMigration",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureLength",
      inputs: [
            {
                  name: "length",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureS",
      inputs: [
            {
                  name: "s",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyEvidenceHash",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidNonce",
      inputs: [
            {
                  name: "signer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "provided",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "expected",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "InvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "MigrationNotFound",
      inputs: [
            {
                  name: "migrationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "NotMigrator",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "SameAlgorithm",
      inputs: [
            {
                  name: "algorithm",
                  type: "string",
                  internalType: "string",
                },
          ],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ZeroAssetRegistry",
      inputs: [],
    }
] as const;

export const AuditRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "AUDITOR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAudit",
      inputs: [
            {
                  name: "auditId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct AuditRegistry.AuditAttestation",
                  components: [
                        {
                              name: "orgDid",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "auditorDid",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "result",
                              type: "uint8",
                              internalType: "enum AuditRegistry.AuditResult",
                            },
                        {
                              name: "assetsReviewed",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "assetsMigrated",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "reportHash",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "reportURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAuditsByAuditor",
      inputs: [
            {
                  name: "auditorDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAuditsByOrg",
      inputs: [
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32[]",
                  internalType: "bytes32[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getLatestAudit",
      inputs: [
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "exists",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "result",
                  type: "uint8",
                  internalType: "enum AuditRegistry.AuditResult",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [
            {
                  name: "migrationRegistry_",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "migrationRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract MigrationRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "postAudit",
      inputs: [
            {
                  name: "orgDid",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "result",
                  type: "uint8",
                  internalType: "enum AuditRegistry.AuditResult",
                },
            {
                  name: "assetsReviewed",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "assetsMigrated",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "reportHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "reportURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "auditId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "event",
      name: "AuditPosted",
      inputs: [
            {
                  name: "auditId",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "orgDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "auditorDid",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "result",
                  type: "uint8",
                  indexed: false,
                  internalType: "enum AuditRegistry.AuditResult",
                },
            {
                  name: "assetsReviewed",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "assetsMigrated",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "reportHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "reportURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "AuditNotFound",
      inputs: [
            {
                  name: "auditId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "DuplicateAudit",
      inputs: [
            {
                  name: "auditId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyReportHash",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidCounts",
      inputs: [
            {
                  name: "assetsReviewed",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "assetsMigrated",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "MigratedCountExceedsOnChain",
      inputs: [
            {
                  name: "claimed",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "onChain",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "NotAuditor",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ZeroMigrationRegistry",
      inputs: [],
    }
] as const;

export const QTrustGovernanceAbi = [
    {
      type: "constructor",
      inputs: [
            {
                  name: "timelock_",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "assetRegistry_",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "vendorRegistry_",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "migrationRegistry_",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "auditRegistry_",
                  type: "address",
                  internalType: "address",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_DELAY",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "assetRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract AssetRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "auditRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract AuditRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "execute",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "migrationRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract MigrationRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "schedule",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "scheduleDeactivateVendor",
      inputs: [
            {
                  name: "vendor",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "scheduleGrantRole",
      inputs: [
            {
                  name: "registryIndex",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "schedulePause",
      inputs: [
            {
                  name: "registryIndex",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "scheduleRetireAsset",
      inputs: [
            {
                  name: "assetId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "scheduleUnpause",
      inputs: [
            {
                  name: "registryIndex",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "timelock",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract TimelockController",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "vendorRegistry",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "contract VendorRegistry",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "event",
      name: "GovernanceCallScheduled",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  indexed: false,
                  internalType: "bytes",
                },
            {
                  name: "delay",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    }
] as const;

export const TimelockControllerAbi = [
    {
      type: "constructor",
      inputs: [
            {
                  name: "minDelay",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "proposers",
                  type: "address[]",
                  internalType: "address[]",
                },
            {
                  name: "executors",
                  type: "address[]",
                  internalType: "address[]",
                },
            {
                  name: "admin",
                  type: "address",
                  internalType: "address",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "receive",
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "CANCELLER_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "EXECUTOR_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "PROPOSER_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "cancel",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "execute",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "value",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "payload",
                  type: "bytes",
                  internalType: "bytes",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "executeBatch",
      inputs: [
            {
                  name: "targets",
                  type: "address[]",
                  internalType: "address[]",
                },
            {
                  name: "values",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
            {
                  name: "payloads",
                  type: "bytes[]",
                  internalType: "bytes[]",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "getMinDelay",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getOperationState",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint8",
                  internalType: "enum TimelockController.OperationState",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getTimestamp",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "hashOperation",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "value",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "pure",
    },
    {
      type: "function",
      name: "hashOperationBatch",
      inputs: [
            {
                  name: "targets",
                  type: "address[]",
                  internalType: "address[]",
                },
            {
                  name: "values",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
            {
                  name: "payloads",
                  type: "bytes[]",
                  internalType: "bytes[]",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "pure",
    },
    {
      type: "function",
      name: "isOperation",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "isOperationDone",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "isOperationPending",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "isOperationReady",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "onERC1155BatchReceived",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
            {
                  name: "",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
            {
                  name: "",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "onERC1155Received",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "onERC721Received",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "schedule",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "value",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "delay",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "scheduleBatch",
      inputs: [
            {
                  name: "targets",
                  type: "address[]",
                  internalType: "address[]",
                },
            {
                  name: "values",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
            {
                  name: "payloads",
                  type: "bytes[]",
                  internalType: "bytes[]",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "delay",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "updateDelay",
      inputs: [
            {
                  name: "newDelay",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "event",
      name: "CallExecuted",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "index",
                  type: "uint256",
                  indexed: true,
                  internalType: "uint256",
                },
            {
                  name: "target",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
            {
                  name: "value",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "data",
                  type: "bytes",
                  indexed: false,
                  internalType: "bytes",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "CallSalt",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "salt",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "CallScheduled",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "index",
                  type: "uint256",
                  indexed: true,
                  internalType: "uint256",
                },
            {
                  name: "target",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
            {
                  name: "value",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "data",
                  type: "bytes",
                  indexed: false,
                  internalType: "bytes",
                },
            {
                  name: "predecessor",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "delay",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Cancelled",
      inputs: [
            {
                  name: "id",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "MinDelayChange",
      inputs: [
            {
                  name: "oldDuration",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "newDuration",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "TimelockInsufficientDelay",
      inputs: [
            {
                  name: "delay",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "minDelay",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "TimelockInvalidOperationLength",
      inputs: [
            {
                  name: "targets",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "payloads",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "values",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "TimelockUnauthorizedCaller",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "TimelockUnexecutedPredecessor",
      inputs: [
            {
                  name: "predecessorId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "TimelockUnexpectedOperationState",
      inputs: [
            {
                  name: "operationId",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "expectedStates",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export const RevocationAnchorAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "EIP712_VERSION_HASH",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "ISSUER_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "deactivateIssuer",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "domainSeparator",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAllIssuers",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address[]",
                  internalType: "address[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getIssuer",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct RevocationAnchor.IssuerInfo",
                  components: [
                        {
                              name: "issuerDid",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "currentRoot",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "previousRoot",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "lastUpdated",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRevocationRoot",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "hashTypedRootUpdate",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "newRoot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "isIssuerActive",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "issuerCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "nonces",
      inputs: [
            {
                  name: "",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "registerIssuer",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "issuerDid",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "updateRoot",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "newRoot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "previousRoot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "updateRootSigned",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "newRoot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "nonce",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "signature",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [
            {
                  name: "previousRoot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "IssuerRegistered",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "issuerDid",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RevocationRootUpdated",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "newRoot",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "previousRoot",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureLength",
      inputs: [
            {
                  name: "length",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "ECDSAInvalidSignatureS",
      inputs: [
            {
                  name: "s",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyRoot",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidNonce",
      inputs: [
            {
                  name: "signer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "provided",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "expected",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "InvalidSignature",
      inputs: [],
    },
    {
      type: "error",
      name: "IssuerNotRegistered",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export const PolicyCommitmentAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "POLICY_AUTHORITY_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "commitPolicy",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "policyHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "policyURI",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "deactivatePolicy",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "getAllPolicyIds",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string[]",
                  internalType: "string[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getPolicyInfo",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct PolicyCommitment.PolicyInfo",
                  components: [
                        {
                              name: "latestVersion",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "totalVersions",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "exists",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getPolicyVersion",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct PolicyCommitment.PolicyVersion",
                  components: [
                        {
                              name: "policyId",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "version",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "policyHash",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "policyURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "committedBy",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getVersionsByPolicyId",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "policyCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "verifyPolicy",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "policyHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "PolicyCommitted",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  indexed: true,
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  indexed: true,
                  internalType: "uint256",
                },
            {
                  name: "policyHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "policyURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "committedBy",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "PolicyDeactivated",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  indexed: true,
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  indexed: true,
                  internalType: "uint256",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyPolicyHash",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "NotPolicyAuthority",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "PolicyAlreadyExists",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
    },
    {
      type: "error",
      name: "PolicyNotFound",
      inputs: [
            {
                  name: "policyId",
                  type: "string",
                  internalType: "string",
                },
          ],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export const SchemaRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "SCHEMA_AUTHORITY_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "addEquivalence",
      inputs: [
            {
                  name: "fromSchemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "toSchemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "equivalenceType",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "deactivateSchema",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "getAllSchemaIds",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string[]",
                  internalType: "string[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getEquivalences",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple[]",
                  internalType: "struct SchemaRegistry.EquivalenceMapping[]",
                  components: [
                        {
                              name: "fromSchemaId",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "toSchemaId",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "equivalenceType",
                              type: "string",
                              internalType: "string",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getSchema",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct SchemaRegistry.SchemaInfo",
                  components: [
                        {
                              name: "schemaId",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "version",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "schemaHash",
                              type: "bytes32",
                              internalType: "bytes32",
                            },
                        {
                              name: "schemaURI",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "schemaType",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "registeredBy",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getSchemaEntry",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct SchemaRegistry.SchemaEntry",
                  components: [
                        {
                              name: "latestVersion",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "totalVersions",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "exists",
                              type: "bool",
                              internalType: "bool",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getVersionsBySchemaId",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "uint256[]",
                  internalType: "uint256[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "registerSchema",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "schemaHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "schemaURI",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "schemaType",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "schemaCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "verifySchema",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  internalType: "uint256",
                },
            {
                  name: "schemaHash",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "SchemaEquivalenceAdded",
      inputs: [
            {
                  name: "fromSchemaId",
                  type: "string",
                  indexed: true,
                  internalType: "string",
                },
            {
                  name: "toSchemaId",
                  type: "string",
                  indexed: true,
                  internalType: "string",
                },
            {
                  name: "equivalenceType",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "SchemaRegistered",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  indexed: true,
                  internalType: "string",
                },
            {
                  name: "version",
                  type: "uint256",
                  indexed: true,
                  internalType: "uint256",
                },
            {
                  name: "schemaHash",
                  type: "bytes32",
                  indexed: false,
                  internalType: "bytes32",
                },
            {
                  name: "schemaURI",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "schemaType",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "registeredBy",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptySchemaHash",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "NotSchemaAuthority",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "SchemaAlreadyExists",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
          ],
    },
    {
      type: "error",
      name: "SchemaNotFound",
      inputs: [
            {
                  name: "schemaId",
                  type: "string",
                  internalType: "string",
                },
          ],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export const TrustAnchorRegistryAbi = [
    {
      type: "constructor",
      inputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "DEFAULT_ADMIN_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "GOVERNANCE_ROLE",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "UPGRADE_INTERFACE_VERSION",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "string",
                  internalType: "string",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "accreditIssuer",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "issuerDid",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "scope",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "validFor",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "accreditedIssuerCount",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAccreditation",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "tuple",
                  internalType: "struct TrustAnchorRegistry.IssuerAccreditation",
                  components: [
                        {
                              name: "issuer",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "issuerDid",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "scope",
                              type: "string",
                              internalType: "string",
                            },
                        {
                              name: "validFrom",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "validUntil",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "accreditedBy",
                              type: "address",
                              internalType: "address",
                            },
                        {
                              name: "timestamp",
                              type: "uint256",
                              internalType: "uint256",
                            },
                        {
                              name: "active",
                              type: "bool",
                              internalType: "bool",
                            },
                        {
                              name: "revocationReason",
                              type: "string",
                              internalType: "string",
                            },
                      ],
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getAllAccreditedIssuers",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "address[]",
                  internalType: "address[]",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "getRoleAdmin",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "grantRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "hasRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "initialize",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "isIssuerAccredited",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "pause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "paused",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "proxiableUUID",
      inputs: [],
      outputs: [
            {
                  name: "",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "reaccreditIssuer",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "additionalTime",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "renounceRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "callerConfirmation",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeAccreditation",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "reason",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "revokeRole",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
          ],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "supportsInterface",
      inputs: [
            {
                  name: "interfaceId",
                  type: "bytes4",
                  internalType: "bytes4",
                },
          ],
      outputs: [
            {
                  name: "",
                  type: "bool",
                  internalType: "bool",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "function",
      name: "unpause",
      inputs: [],
      outputs: [],
      stateMutability: "nonpayable",
    },
    {
      type: "function",
      name: "upgradeToAndCall",
      inputs: [
            {
                  name: "newImplementation",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "data",
                  type: "bytes",
                  internalType: "bytes",
                },
          ],
      outputs: [],
      stateMutability: "payable",
    },
    {
      type: "function",
      name: "verifyAccreditation",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "scope",
                  type: "string",
                  internalType: "string",
                },
          ],
      outputs: [
            {
                  name: "accredited",
                  type: "bool",
                  internalType: "bool",
                },
            {
                  name: "issuerDid",
                  type: "string",
                  internalType: "string",
                },
            {
                  name: "validUntil",
                  type: "uint256",
                  internalType: "uint256",
                },
          ],
      stateMutability: "view",
    },
    {
      type: "event",
      name: "Initialized",
      inputs: [
            {
                  name: "version",
                  type: "uint64",
                  indexed: false,
                  internalType: "uint64",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "IssuerAccreditationRevoked",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "reason",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "IssuerAccredited",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "issuerDid",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "scope",
                  type: "string",
                  indexed: false,
                  internalType: "string",
                },
            {
                  name: "validFrom",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "validUntil",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "accreditedBy",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "IssuerReaccredited",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "newValidUntil",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
            {
                  name: "timestamp",
                  type: "uint256",
                  indexed: false,
                  internalType: "uint256",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Paused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleAdminChanged",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "previousAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "newAdminRole",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleGranted",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "RoleRevoked",
      inputs: [
            {
                  name: "role",
                  type: "bytes32",
                  indexed: true,
                  internalType: "bytes32",
                },
            {
                  name: "account",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
            {
                  name: "sender",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Unpaused",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  indexed: false,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "event",
      name: "Upgraded",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  indexed: true,
                  internalType: "address",
                },
          ],
      anonymous: false,
    },
    {
      type: "error",
      name: "AccessControlBadConfirmation",
      inputs: [],
    },
    {
      type: "error",
      name: "AccessControlUnauthorizedAccount",
      inputs: [
            {
                  name: "account",
                  type: "address",
                  internalType: "address",
                },
            {
                  name: "neededRole",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    },
    {
      type: "error",
      name: "AddressEmptyCode",
      inputs: [
            {
                  name: "target",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967InvalidImplementation",
      inputs: [
            {
                  name: "implementation",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "ERC1967NonPayable",
      inputs: [],
    },
    {
      type: "error",
      name: "EmptyIssuerDid",
      inputs: [],
    },
    {
      type: "error",
      name: "EnforcedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "ExpectedPause",
      inputs: [],
    },
    {
      type: "error",
      name: "FailedCall",
      inputs: [],
    },
    {
      type: "error",
      name: "InvalidInitialization",
      inputs: [],
    },
    {
      type: "error",
      name: "IssuerAlreadyAccredited",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "IssuerNotAccredited",
      inputs: [
            {
                  name: "issuer",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "NotGovernance",
      inputs: [
            {
                  name: "caller",
                  type: "address",
                  internalType: "address",
                },
          ],
    },
    {
      type: "error",
      name: "NotInitialized",
      inputs: [],
    },
    {
      type: "error",
      name: "NotInitializing",
      inputs: [],
    },
    {
      type: "error",
      name: "ReentrancyGuardReentrantCall",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnauthorizedCallContext",
      inputs: [],
    },
    {
      type: "error",
      name: "UUPSUnsupportedProxiableUUID",
      inputs: [
            {
                  name: "slot",
                  type: "bytes32",
                  internalType: "bytes32",
                },
          ],
    }
] as const;

export function auditResultName(code: number): string {
  switch (code) {
    case 0: return "Pending";
    case 1: return "Passed";
    case 2: return "Failed";
    case 3: return "Conditional";
    default: return "Unknown";
  }
}
