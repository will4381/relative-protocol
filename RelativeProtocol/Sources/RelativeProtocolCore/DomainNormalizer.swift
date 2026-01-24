// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Darwin
import Foundation

public enum DomainNormalizer {
    private static let twoPartTlds: Set<String> = [
        "ac.uk",
        "co.uk",
        "gov.uk",
        "org.uk",
        "co.jp",
        "co.kr",
        "co.in",
        "co.nz",
        "com.au",
        "net.au",
        "org.au",
        "com.br",
        "com.mx",
        "com.ar",
        "com.cn",
        "com.hk",
        "com.tw",
        "com.my",
        "com.sg",
        "com.tr",
        "com.sa"
    ]

    public static func registrableDomain(from name: String?) -> String? {
        guard var name else { return nil }
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !name.isEmpty else { return nil }
        guard !isIPAddress(name) else { return nil }

        let labels = name.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return name }

        let suffix = labels.suffix(2).joined(separator: ".")
        let needsThreeLabels = twoPartTlds.contains(suffix)
        if needsThreeLabels, labels.count >= 3 {
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
