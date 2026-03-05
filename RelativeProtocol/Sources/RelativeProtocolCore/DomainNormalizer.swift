// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation

public enum DomainNormalizer {
    private static let commonSecondLevelPublicSuffixes: Set<String> = [
        "ac",
        "co",
        "com",
        "edu",
        "gov",
        "mil",
        "net",
        "nom",
        "org",
        "sch"
    ]

    public static func registrableDomain(from name: String?) -> String? {
        guard var name else { return nil }
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !name.isEmpty else { return nil }
        guard !isIPAddress(name) else { return nil }

        let labels = name.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return name }

        let topLevelDomain = labels[labels.count - 1]
        let secondLevelDomain = labels[labels.count - 2]
        let needsThreeLabels = labels.count >= 3
            && topLevelDomain.count == 2
            && commonSecondLevelPublicSuffixes.contains(secondLevelDomain)
        if needsThreeLabels {
            return labels.suffix(3).joined(separator: ".")
        }
        return labels.suffix(2).joined(separator: ".")
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var addr = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 {
            return true
        }
        var addr6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 {
            return true
        }
        return false
    }
}
