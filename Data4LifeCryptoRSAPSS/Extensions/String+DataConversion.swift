//
//  String+DataConversion.swift
//  SwCrypt
//
//  Created by Alessio Borraccino on 03.09.21.
//  Copyright © 2021 irl. All rights reserved.
//

import Foundation

extension String {

    /// Create Data from hexadecimal string representation
    ///
    /// This takes a hexadecimal representation and creates a Data object. Note, if the string has
    /// any spaces, those are removed. Also if the string started with a '<' or ended with a '>',
    /// those are removed, too. This does no validation of the string to ensure it's a valid
    /// hexadecimal string
    ///
    /// The use of `strtoul` inspired by Martin R at http://stackoverflow.com/a/26284562/1271826
    ///
    /// - returns: Data represented by this hexadecimal string.
    ///            Returns nil if string contains characters outside the 0-9 and a-f range.

    func dataFromHexadecimalString() -> Data? {
        let trimmedString = self.trimmingCharacters(
            in: CharacterSet(charactersIn: "<> ")).replacingOccurrences(
                of: " ", with: "")

        // make sure the cleaned up string consists solely of hex digits,
        // and that we have even number of them

        let regex = try! NSRegularExpression(pattern: "^[0-9a-f]*$", options: .caseInsensitive)

        let found = regex.firstMatch(in: trimmedString, options: [],
                                     range: NSRange(location: 0,
                                                    length: trimmedString.count))
        guard found != nil &&
                found?.range.location != NSNotFound &&
                trimmedString.count % 2 == 0 else {
            return nil
        }

        // everything ok, so now let's build Data

        var data = Data(capacity: trimmedString.count / 2)
        var index: String.Index? = trimmedString.startIndex

        while let i = index {
            let byteString = String(trimmedString[i ..< trimmedString.index(i, offsetBy: 2)])
            let num = UInt8(byteString.withCString { strtoul($0, nil, 16) })
            data.append([num] as [UInt8], count: 1)

            index = trimmedString.index(i, offsetBy: 2, limitedBy: trimmedString.endIndex)
            if index == trimmedString.endIndex { break }
        }

        return data
    }
}
