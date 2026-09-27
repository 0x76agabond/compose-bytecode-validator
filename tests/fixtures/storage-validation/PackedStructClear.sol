// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract PackedStructClear {
    bytes32 internal constant STORAGE_POSITION = keccak256("compose.fixture.packed-struct-clear");

    struct FacetNode {
        address facet;
        bytes4 previousId;
        bytes4 nextId;
    }

    struct Storage {
        mapping(bytes4 selector => FacetNode node) nodes;
    }

    function clearNode(bytes4 selector) external {
        delete getStorage().nodes[selector];
    }

    function clearPreviousId(bytes4 selector) external {
        delete getStorage().nodes[selector].previousId;
    }

    function getStorage() internal pure returns (Storage storage s) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }
}
