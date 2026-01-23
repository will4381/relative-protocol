import os

public enum RelativeLogCategory: String {
    case tunnel
    case parser
    case metrics
    case flow
}

public enum RelativeLog {
    public static func logger(_ category: RelativeLogCategory) -> Logger {
        Logger(subsystem: "com.relative.protocol", category: category.rawValue)
    }
}
