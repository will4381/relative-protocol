import Darwin
import Foundation

/// Normalizes hostnames into registrable domains for stable analytics classification keys.
public enum DomainNormalizer {
    private static let twoPartTLDs: Set<String> = [
        "ac.uk", "co.uk", "gov.uk", "org.uk", "co.jp", "co.kr", "co.in", "co.nz",
        "com.au", "net.au", "org.au", "com.br", "com.mx", "com.ar", "com.cn", "com.hk",
        "com.tw", "com.my", "com.sg", "com.tr", "com.sa"
    ]
    private static let cache = BoundedCache<String, String>(countLimit: 4_096)

    public static func registrableDomain(from name: String?) -> String? {
        guard var name else { return nil }
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !name.isEmpty else { return nil }
        guard !isIPAddress(name) else { return nil }

        if let cached = cache.value(for: name) {
            return cached
        }

        let labels = name.split(separator: ".").map(String.init)
        guard labels.count >= 2 else {
            cache.insert(name, for: name)
            return name
        }

        let suffix = labels.suffix(2).joined(separator: ".")
        if twoPartTLDs.contains(suffix), labels.count >= 3 {
            let result = labels.suffix(3).joined(separator: ".")
            cache.insert(result, for: name)
            return result
        }
        let result = labels.suffix(2).joined(separator: ".")
        cache.insert(result, for: name)
        return result
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
